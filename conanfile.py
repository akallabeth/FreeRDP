from conans import ConanFile, CMake, tools
from conan.tools.cmake import CMakeToolchain, CMakeDeps

class FreerdpConan(ConanFile):
    name = "freerdp"
    version = "3.0.0"
    license = "Apache-2.0"
    author = "team@freerdp.com"
    url = "https://github.com/freerdp/freerdp"
    description = "FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license. Enjoy the freedom of using your software wherever you want, the way you want it, in a world where interoperability can finally liberate your computing experience."
    topics = ("rdp", "remote-desktop")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": True, "fPIC": True}
    generators = 'CMakeToolchain'
    build_requires = "openssl/1.1.1k", "openh264/2.1.1", "nasm/2.15.05", "libusb/1.0.24", "zlib/1.2.11", "ninja/1.10.2", "cmake/3.20.2"

    def init(self):
        pass

    def build_requirements(self):
        if self.settings.os == 'Windows':
            self.build_requires('')
        elif self.settings.os == 'Macos':
            self.build_requires('icu/68.2')
        elif self.settings.os == 'Linux':
            self.build_requires('icu/68.2')
        elif self.settings.os == 'Android':
            self.build_requires('')
        else:
            self.build_requires('')

    def config_options(self):
        pass

    def source(self):
        pass

    def _configure_cmake(self):
        cmake = CMake(self)
        cmake.verbose = True
        cmake.cmake_generator='Ninja'
        cmake.definitions["BUILD_TESTING"] = "ON"
        cmake.definitions["WITH_CLIENT"] = "OFF"
        cmake.definitions["WITH_MANPAGES"] = "OFF"
        cmake.definitions["WITH_WAYLAND"] = "OFF"
        cmake.definitions["WITH_PROXY"] = "OFF"
        cmake.definitions["WITH_SAMPLE"] = "OFF"
        cmake.definitions["WITH_SHADOW"] = "OFF"
        cmake.definitions["WITH_WINPR_TOOLS"] = "OFF"
        cmake.definitions["WITH_SERVER"] = "ON"
        cmake.definitions["WITH_OPENH264"] = "OFF"
        cmake.definitions["WITH_ICU"] = "ON"
        if self.options.shared:
            cmake.definitions['BUILD_SHARED_LIBS'] = 'ON'
        else:
            cmake.definitions['BUILD_SHARED_LIBS'] = 'OFF'

        cmake.configure()
        return cmake

    def generate(self):
        cmake = CMakeToolchain(self)
        cmake.generate()

        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()
        cmake.test()

    def package(self):
        cmake = self._configure_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["freerdp"]

