import nox
from nox import Session


@nox.session
@nox.parametrize("salt", ["3006", "3007"])
def test(s: Session, salt: str) -> None:
    s.install(
        "--verbose",
        ".",
        f"salt~={salt}.0",
        "--group=test",
        env={"PIP_CONSTRAINT": "test/constraints.txt"},
    )

    s.run("pip", "list")

    s.run("salt", "--versions-report")
    s.run("pytest", *s.posargs)


@nox.session
def lint(s: Session) -> None:
    s.install("--group=lint")
    s.run("pip", "list")

    s.run("ruff", "check", "--diff", "--no-fix", ".")
    s.run("ruff", "format", "--diff", "--check", ".")
