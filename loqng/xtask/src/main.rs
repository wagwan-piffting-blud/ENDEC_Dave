//! Reverse-engineering and differential-testing tools for `loqng`.
//!
//! ```text
//! cargo run -p xtask -- data              parse the voice tree, report what reads
//! cargo run -p xtask -- probe             find which trace switches produce output
//! cargo run -p xtask -- capture           build the reference corpus
//! cargo run -p xtask -- replay <stage>    diff a Rust stage against the corpus
//! ```
//!
//! Arguments are parsed by hand. The workspace has no external dependencies and
//! that is worth more than a nicer flag parser.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod capture;
mod concat;
mod data;
mod decode;
mod engbench;
mod engcorpus;
mod engprobe;
mod engprof;
mod engrun;
mod fon;
mod fonprobe;
mod join;
mod modbases;
mod probe;
mod refpcm;
mod replay;
mod seqlen;
mod sigprobe;
mod verify;
mod voicebank;

pub struct Paths {
    pub lib_dir: PathBuf,
    pub data_dir: PathBuf,
    pub corpus: PathBuf,
}

const USAGE: &str = "\
xtask — loqng reverse-engineering tools

USAGE:
    cargo run -p xtask -- <command> [options]

COMMANDS:
    data                 Parse every data file in the voice tree and report
    probe [text]         Turn each trace switch on alone and report what it emits
    capture [options]    Speak the corpus through the ARM oracle and save the results
    replay <stage>       Diff the Rust stage against the saved corpus
    decode [options]     Decode a voice bank with the ported codec, write a WAV
    concat               Render captured utterances from their Cat unit lists
    join                 Recover the crossfade weights at a unit boundary
    fon [--why] [-v]     Diff the ported phoneme narrowing against the engine
    fonprobe [--minimise n slot]
                         Call the phoneme mapper directly as a pure function
                         (--xlate N: hold fon::exact to it)
    sigprobe [cases]     Hold the translated SEQUENS functions to the ARM
    engprobe [cases]     Hold the whole-module translation to the ARM
    modbases             Print where the oracle loads each engine module
    engrun [text] [--file <path>|-] [--out <raw>]
                         Speak with the TRANSLATED engine — no ARM at all
    engbench [--limit]   Exact timings, scaling, and the length ceiling
    engprof [--chars n] [--top n]
                         Where the time goes (build --features xrt-prof)
    engcorpus [--limit N]
                         Speak the whole corpus natively and diff the audio
    seqlen              Measure the true output length of SEQUENS units
    refpcm               Diff the ported codec against the ARM module (the gate)
    verify               Prove ported routines bit-exact vs the ARM original

OPTIONS:
    --lib <dir>          Engine modules   [default: engine/lib]
    --data <dir>         Voice tree       [default: engine/data]
    --corpus <dir>       Corpus root      [default: ./corpus]
    --texts <file>       One sentence per line; default is the built-in set
    --limit <n>          Stop after n sentences
    --bank <file>        decode: voice bank  [default: Dave-19200.16000.loqmsx.bin]
    --start <n>          decode: first frame [default: 0]
    --frames <n>         decode: how many    [default: 400]
    --out <file>         decode: WAV path    [default: ./decode.wav]
    -h, --help           This
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let cmd = args[0].clone();
    let rest = &args[1..];

    let paths = match resolve_paths(rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("xtask: {e}");
            return ExitCode::FAILURE;
        }
    };

    let r = match cmd.as_str() {
        "data" => data::run(&paths),
        "probe" => probe::run(&paths, positional(rest)),
        "capture" => capture::run(&paths, rest),
        "replay" => replay::run(&paths, positional(rest)),
        "decode" => decode::run(&paths, rest),
        "concat" => concat::run(&paths, rest),
        "join" => join::run(&paths, rest),
        "fon" => fon::run(&paths, rest),
        "fonprobe" => fonprobe::run(&paths, rest),
        "sigprobe" => sigprobe::run(&paths, rest),
        "modbases" => modbases::run(&paths, rest),
        "engprobe" => engprobe::run(&paths, rest),
        "engrun" => engrun::run(&paths, rest),
        "engcorpus" => engcorpus::run(&paths, rest),
        "engbench" => engbench::run(&paths, rest),
        "engprof" => engprof::run(&paths, rest),
        "seqlen" => seqlen::run(&paths, rest),
        "refpcm" => refpcm::run(&paths, rest),
        "verify" => verify::run(&paths),
        other => Err(format!("unknown command `{other}`; try --help")),
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The first argument that is not a flag or a flag's value.
fn positional(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            i += 2;
            continue;
        }
        return Some(args[i].clone());
    }
    None
}

pub fn flag(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == name {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

/// Locate the engine and the voice tree.
///
/// The defaults are `engine/` in the workspace, the same tree
/// `loqng-voice/build.rs` bakes in. `$LOQ_LIB` and `$LOQ_DATA` override,
/// matching the environment variables `loqdave` already honours.
fn resolve_paths(args: &[String]) -> Result<Paths, String> {
    let root = workspace_root();
    let sibling = root.join("engine");

    let lib_dir = flag(args, "--lib")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOQ_LIB").map(PathBuf::from))
        .unwrap_or_else(|| sibling.join("lib"));

    let data_dir = flag(args, "--data")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOQ_DATA").map(PathBuf::from))
        .unwrap_or_else(|| sibling.join("data"));

    let corpus = flag(args, "--corpus")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("corpus"));

    if !lib_dir.join("LoqTTS6.so").is_file() {
        return Err(format!(
            "no LoqTTS6.so in {} — pass --lib or set LOQ_LIB",
            lib_dir.display()
        ));
    }
    if !data_dir.is_dir() {
        return Err(format!(
            "no voice tree at {} — pass --data or set LOQ_DATA",
            data_dir.display()
        ));
    }

    Ok(Paths {
        lib_dir,
        data_dir,
        corpus,
    })
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
