raise Exception(
    "Don't use `poetry build`, it can't build abi stable wheels. "
    "Use `poetry run python -m build -w` instead."
)
