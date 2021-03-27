#!/usr/bin/env python3
# pylint: disable=inherit-non-class
from argparse import ArgumentParser
from base64 import b64encode, b64decode
import os
import subprocess
import sys
from typing import NamedTuple, Optional

# pip install bcrypt / pacman -S python-bcrypt
# checked with version 3.2.0
import bcrypt
# pip install pyyaml
import yaml

CODEC = "ascii"
# DEFAULT_CONFIG = "/etc/yubikey-auth.conf"
DEFAULT_CONFIG = os.path.expanduser("~/.config/yubikey-auth.conf")
DEFAULT_SLOT = 2


class Args(NamedTuple):
    slot: int
    config_path: str
    add_key: bool
    remove_key: bool
    generate_config: bool


class Config(NamedTuple):
    # A random challenge
    challenge: str
    # The bcrypt hashes of the responses to the challenge.
    # Each entry corresponds to one key
    valid_hashes: list[str]


def main(args: Args):
    new_config = None
    if args.generate_config:
        new_config = generate_config(args)
    else:
        config = parse_config(args.config_path)
        password = challenge_response(args.slot, config.challenge)

        if args.add_key:
            new_config = add_key(config, password)
        elif args.remove_key:
            new_config = remove_key(config, password)
        else:
            verify_key(config, password)

    if new_config:
        write_config(args.config_path, new_config)


def get_matching_index(password: str, valid_hashes: list[str]) -> Optional[int]:
    for index, current_hash in enumerate(valid_hashes):
        if is_matching_hash(password, current_hash):
            return index
    return None


def challenge_response(slot: int, challenge: str) -> str:
    response_bytes = subprocess.check_output(
        ["ykchalresp", f"-{slot}", challenge])
    response_hex = response_bytes.decode(CODEC).strip()
    return response_hex


def add_key(config: Config, password: str) -> Optional[Config]:
    if get_matching_index(password, config.valid_hashes) != None:
        print("The key is already registered in the config file")
        return None
    else:
        valid_hashes = config.valid_hashes + [generate_hash(password)]
        return config._replace(valid_hashes=valid_hashes)


def remove_key(config: Config, password: str) -> Optional[Config]:
    hash_index = get_matching_index(password, config.valid_hashes)
    if hash_index != None:
        valid_hashes = list(config.valid_hashes)
        del valid_hashes[hash_index]
        return config._replace(valid_hashes=valid_hashes)
    else:
        print("The key was not registered in the config file")
        return None


def verify_key(config: Config, password: str) -> None:
    if get_matching_index(password, config.valid_hashes) == None:
        print("The key is not registered in the config file")
        sys.exit(1)


def generate_config(args: Args) -> Config:
    random_bytes = os.urandom(20)
    challenge = b64encode(random_bytes).decode(CODEC)
    password = challenge_response(args.slot, challenge)
    config = Config(challenge=challenge, valid_hashes=[])
    return add_key(config, password) or config


def parse_args(args: list[str]) -> Args:
    parser = ArgumentParser(
        description="Checks if a valid (registered) yubikey is used. If you have to touch your key for the challenge-response slot, you have to touch the key when it starts blinking.")
    parser.add_argument("-s", "--slot", type=int,
                        help=f"the yubikeys otp slot number. Defaults to {DEFAULT_SLOT}", default=DEFAULT_SLOT)
    parser.add_argument(
        "-c", "--config", help=f"the config file. Defaults to '{DEFAULT_CONFIG}'", default=DEFAULT_CONFIG)

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-g", "--generate", action="store_true",
                              help="generate a new config file with only the current key. This overwrites the existing config file")
    action_group.add_argument("-a", "--add-key", action="store_true",
                              help="adds the current key to the config file")
    action_group.add_argument("-r", "--remove-key", action="store_true",
                              help="remove the current key from the config file")
    a = parser.parse_args(args)
    return Args(add_key=a.add_key, config_path=a.config, generate_config=a.generate, remove_key=a.remove_key, slot=a.slot)

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
