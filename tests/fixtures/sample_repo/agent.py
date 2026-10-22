"""Deliberately unsafe test input. Never import or execute this fixture."""

import subprocess


def unsafe_tool(user_input: str) -> None:
    subprocess.run(user_input, shell=True)
