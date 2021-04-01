#!/usr/bin/env python3
# pylint: disable=inherit-non-class
from argparse import ArgumentParser
from base64 import b64encode, b64decode
import os
import subprocess
import sys
import traceback
from typing import NamedTuple, Optional

# pip install bcrypt / pacman -S python-bcrypt
# checked with version 3.2.0
import bcrypt
# pip install pyyaml
import yaml

INDEX_NONE = -1
CODEC = "ascii"
# DEFAULT_CONFIG = "/etc/yubikey-auth.conf"
DEFAULT_CONFIG = os.path.expanduser("~/.config/yubikey-auth.conf")
DEFAULT_SLOT = 2


class Args(NamedTuple):
    command: str
    config_path: str
    debug: bool
    slot: int


class Config(NamedTuple):
    # A random challenge
    challenge: str
    # The bcrypt hashes of the responses to the challenge.
    # Each entry corresponds to one key
    valid_hashes: list[str]


class ExitWithError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class YubikeyAuth:
    def __init__(self, config_path: str = DEFAULT_CONFIG, otp_slot: int = DEFAULT_SLOT, debug: bool = False):
        self.config_path = config_path
        self.otp_slot = otp_slot
        self.debug = debug
        self.config_or_none: Optional[Config] = None
        self.config_changed = False

    def ensure_config_loaded(self) -> Config:
        if not self.config_or_none:
            try:
                self.config_or_none = parse_config(self.config_path)
                self.config_changed = False
            except Exception as e:
                raise ExitWithError(f"Error reading config to '{self.config_path}': {e}")
            print_debug(f"Read config: {self.config_or_none}", self.debug)
        return self.config_or_none

    def set_config(self, config) -> None:
        self.config_or_none = config
        self.config_changed = True

    def write_config_if_changed(self) -> None:
        if self.config_or_none and self.config_changed:
            try:
                write_config(self.config_path, self.config_or_none)
                self.config_changed = False
            except Exception as e:
                raise ExitWithError(f"Error writing config to '{self.config_path}': {e}")
            print_debug(f"Wrote config: {self.config_or_none}", self.debug)

    def challenge_response(self) -> tuple[Config, str]:
        config = self.ensure_config_loaded()
        print("If your Yubikey starts blinking, please touch it now!")
        try:
            response_bytes = subprocess.check_output(
                ["ykchalresp", f"-{self.otp_slot}", config.challenge])
        except subprocess.CalledProcessError:
            raise ExitWithError("Failed to communicate with the Yubikey. Did you specify the correct slot and touched the key when it blinked?")
        response_hex = response_bytes.decode(CODEC).strip()
        return (config, response_hex)

    def add_key(self) -> None:
        config, password = self.challenge_response()
        if get_matching_index(password, config.valid_hashes) != INDEX_NONE:
            raise ExitWithError("The key is already registered in the config file")
        else:
            valid_hashes = config.valid_hashes + [generate_hash(password)]
            self.set_config(config._replace(valid_hashes=valid_hashes))

    def remove_key(self) -> None:
        config, password = self.challenge_response()
        index = get_matching_index(password, config.valid_hashes)

        if index != INDEX_NONE:
            valid_hashes = list(config.valid_hashes)
            del valid_hashes[index]
            self.set_config(config._replace(valid_hashes=valid_hashes))
        else:
            raise ExitWithError("The key was not registered in the config file")

    def verify_key(self) -> None:
        config, password = self.challenge_response()

        if get_matching_index(password, config.valid_hashes) == INDEX_NONE:
            raise ExitWithError("The key is not registered in the config file")
        else:
            print("Key verification was successful")

    def generate_config(self) -> None:
        random_bytes = os.urandom(20)
        challenge = b64encode(random_bytes).decode(CODEC)
        # Create a new empty config
        config = Config(challenge=challenge, valid_hashes=[])
        self.set_config(config)
        # Add the current key to it
        self.add_key()


def print_debug(text: str, debug: bool) -> None:
    if debug:
        print("[DEBUG]", text)


def main(args: Args):
    instance = YubikeyAuth(args.config_path, args.slot, args.debug)
    fn = {
        "add": instance.add_key,
        "init": instance.generate_config,
        "remove": instance.remove_key,
        "verify": instance.verify_key,
    }.get(args.command)

    error = False
    try:
        if fn:
            fn()
        else:
            raise Exception(f"Unknown command: '{args.command}'")
    except ExitWithError as e:
        print("Error:", e)
        error = True
    except Exception:
        traceback.print_exc()
        error = True
    finally:
        instance.write_config_if_changed()
        if error:
            sys.exit(1)



def parse_args(args: list[str]) -> Args:
    parser = ArgumentParser(
        description="Checks if a valid (registered) yubikey is used. If you have to touch your key for the challenge-response slot, you have to touch the key when it starts blinking.")
    parser.add_argument("-s", "--slot", type=int,
                        help=f"the yubikeys otp slot number. Defaults to {DEFAULT_SLOT}", default=DEFAULT_SLOT)
    parser.add_argument(
        "-c", "--config", help=f"the config file. Defaults to '{DEFAULT_CONFIG}'", default=DEFAULT_CONFIG)
    parser.add_argument("-d", "--debug", action="store_true", help="show additional debug messages")

    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser(
        "verify", help="check if the key is in the config. Returns exit code 0 (OK) if it exists or code 1 (ERROR) if it does not")
    subparsers.add_parser(
        "init", help="generate a new config file with only the current key. This overwrites the existing config file")
    subparsers.add_parser(
        "add", help="adds the current key to the config file")
    subparsers.add_parser(
        "remove", help="removes the current key from the config file")

    raw = parser.parse_args(args)
    parsed = Args(command=raw.command, config_path=raw.config, debug=raw.debug, slot=raw.slot)
    print_debug(f"Raw arguments: {raw}", parsed.debug)
    print_debug(f"Parsed arguments: {parsed}", parsed.debug)
    return parsed

######################## Hashing functions ##########################


def generate_hash(password: str) -> str:
    password_bytes = password.encode(CODEC)
    salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(password_bytes, salt)
    return hash_bytes.decode(CODEC)


def is_matching_hash(password: str, hash: str) -> bool:
    password_bytes = password.encode(CODEC)
    hash_bytes = hash.encode(CODEC)
    return bcrypt.checkpw(password_bytes, hash_bytes)


def get_matching_index(password: str, valid_hashes: list[str]) -> int:
    for index, current_hash in enumerate(valid_hashes):
        if is_matching_hash(password, current_hash):
            return index
    return -1


######################## I/O functions ##############################


def parse_config(path: str) -> Config:
    with open(path, "rb") as f:
        text = f.read().decode("utf-8")
    config = yaml.safe_load(text)
    return Config(challenge=config["challenge"], valid_hashes=config["valid_hashes"])


def write_config(path: str, config: Config) -> None:
    config_text = yaml.dump({
        "challenge": config.challenge,
        "valid_hashes": config.valid_hashes,
    })
    with open(path, "wb") as f:
        f.write(config_text.encode("utf-8"))

######################## Entry function ##############################


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    main(args)
