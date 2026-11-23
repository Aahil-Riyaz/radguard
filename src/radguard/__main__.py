from radguard.cli import main

# The guard matters: worker processes re-import the main module (Windows "spawn"),
# and without it each worker would run the CLI again.
if __name__ == "__main__":
    raise SystemExit(main())
