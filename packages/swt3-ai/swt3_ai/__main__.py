"""Allow running `python -m swt3_ai` or `python -m swt3_ai <command>`."""

import sys

if len(sys.argv) > 1 and sys.argv[1] in ("init", "doctor", "procedures", "quickstart", "help", "--help", "-h"):
    from .cli import main
    main()
else:
    from .demo import main
    main()
