def build(setup_kwargs):
    setup_kwargs["cffi_modules"] = [
        "build_tanker.py:tanker_ext",
    ]
