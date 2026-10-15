"""The weekly partition job's entry point inside the provisioned bundle. The
pinned writer starts it, as root, with `python3 -I -S -B`:

  partition_weekly.py --run-dir <exec_root>/run-<run_id> --lock-fd N [--docker ABS]

`-I` adds no script directory to sys.path, so this adds its own directory,
and nothing else, before importing anything of the library. The imports this
reaches are exactly partition_weekly.closure's list, which a test pins.
"""

import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
if not sys.path or sys.path[0] != HERE:
    sys.path.insert(0, HERE)


def main(argv):
    import partition_probe as pp
    import partition_run as pr
    opts = dict(zip(argv[0::2], argv[1::2]))
    if len(argv) % 2 or set(opts) - {"--run-dir", "--lock-fd", "--docker"} or {"--run-dir", "--lock-fd"} - set(opts):
        print("usage: partition_weekly.py --run-dir DIR --lock-fd N [--docker ABS]", file=sys.stderr)
        return pr.INCOMPLETE
    docker = opts.get("--docker", "docker")
    try:
        return pr.run_child(opts["--run-dir"], int(opts["--lock-fd"]), runner=pp.Runner([docker]))
    except pr.ChildError as e:
        print(f"partition-weekly: {e}", file=sys.stderr)
        return pr.INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
