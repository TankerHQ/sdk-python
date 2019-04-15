from conans import ConanFile

native_version = "2.0.0-alpha5"


class SdkPythonConan(ConanFile):
    name = "sdk-python"
    version = "dev"
    author = "Tanker dev team"
    url = "git://github.com/TankerHQ/sdk-python"
    description = "Python bindings for Tanker native SDK"
    settings = "os", "compiler", "build_type", "arch"
    options = {"native_from_sources": [True, False]}
    default_options = "native_from_sources=False", "tanker:tankerlib_shared=False"
    generators = "json"

    def requirements(self):
        if self.options.native_from_sources:
            self.requires("tanker/dev@tanker/testing")
        else:
            self.requires("tanker/%s@tanker/stable" % native_version)

    def imports(self):
        self.copy("*.a", src="lib", dst="lib")
        self.copy("ctanker*", src="include", dst="include")
