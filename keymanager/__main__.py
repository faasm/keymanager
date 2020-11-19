from core import main
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Key Manager for faasm")
    parser.add_argument('--sim', dest='sim', action='store_true', default=False)
    args = parser.parse_args()
    main(args.sim)
