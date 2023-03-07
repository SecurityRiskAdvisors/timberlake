import argparse
from pathlib import Path
from yaml import safe_load

from .config import TimberlakeConfig
from .types import BlockPhase
from .sequence import BasicAttackSequence, VectrAttackSequence
from .log import print_and_log


def cli_main():
    valid_phases = [p.name for p in BlockPhase]
    argparser = argparse.ArgumentParser(prog="timberlake")
    argparser.add_argument("-c", "--config", dest="config", help="config file path", type=str, required=True)
    argparser.add_argument(
        "-p",
        "--phases",
        dest="phases",
        help="list of phases to execute; default = all",
        nargs="+",
        choices=valid_phases,
        default=valid_phases,  # all enum members
    )
    argparser.add_argument("-a", "--args", dest="args", help="args file path", type=str, required=False)
    args = argparser.parse_args()

    if not Path(args.config).exists():
        raise Exception(f"Unknown config path: {args.config}")
    config: TimberlakeConfig = TimberlakeConfig.from_file(args.config)

    overrides = {}
    # TODO: args should be prefixed by a test case name or "global" to allow
    #   test case level overrides or global overrides
    if args.args:
        args_path = Path(args.args)
        if not args_path.exists():
            raise Exception(f"Unknown args path: {args.args}")
        overrides = safe_load(args_path.read_text())

    print_and_log("Timberlake")
    print_and_log("Running phases: " + " ".join(args.phases))

    if config.vectr.use_vectr:
        sequencer = VectrAttackSequence(config=config, phase_names=args.phases)
    else:
        sequencer = BasicAttackSequence(config=config, phase_names=args.phases)
    sequencer.execute(overrides=overrides)


if __name__ == "__main__":
    cli_main()
