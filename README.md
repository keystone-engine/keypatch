Keypatch
========

Keypatch is [the award winning plugin](https://www.hex-rays.com/contests/2016/index.shtml) of [IDA Pro](https://www.hex-rays.com/products/ida/) for [Keystone Assembler Engine](http://keystone-engine.org).

Keypatch consists of 3 tools inside.

- **Patcher** & **Fill Range**: these allow you to type in assembly to directly patch your binary.
- **Search**: this interactive tool let you search for assembly instructions in binary.

See [this quick tutorial](TUTORIAL.md) for how to use Keypatch, and [this slides](Keypatch-slides.pdf) for how it is implemented.

Keypatch is confirmed to work on IDA Pro version 6.4, 6.5, 6.6, 6.8, 6.9, 6.95, 7.0 but should work flawlessly on older versions.
If you find any issues, please [report](http://keystone-engine.org/contact).

--------------------

### 1. Why Keypatch?

Sometimes we want to patch the binary while analyzing it in IDA, but unfortunately the built-in asssembler of IDA Pro is not adequate.

- This tool is not friendly and without many options that would make the life of reverser easier.
- Only X86 assembler is available. Support for all other architectures is totally missing.
- The X86 assembler is not in a good shape, either: it cannot understand many modern Intel instructions.

Keypatch was developed to solve this problem. Thanks to the power of [Keystone](http://keystone-engine.org), our plugin offers some nice features.

- Cross-architecture: support Arm, Arm64 (AArch64/Armv8), Hexagon, Mips, PowerPC, Sparc, SystemZ & X86 (include 16/32/64bit).
- Cross-platform: work everywhere that IDA works, which is on Windows, MacOS, Linux.
- Based on Python, so it is easy to install as no compilation is needed.
- User-friendly: automatically add comments to patched code, and allow reverting (undo) modification.
- Open source under GPL v2.

Keypatch can be the missing piece in your toolset of reverse engineering.

--------------

### 2. Install

- Install Keystone core & Python binding for Python 2.7 from [keystone-engine.org/download](http://keystone-engine.org/download). Or follow the steps in the [appendix section](#appendix-install-keystone-for-ida-pro).

- Copy file `keypatch.py` to IDA Plugin folder, then restart IDA Pro to use Keypatch.
    - On Windows, the folder is at `C:\Program Files (x86)\IDA 6.9\plugins`
    - On MacOS, the folder is at `/Applications/IDA\ Pro\ 6.9/idaq.app/Contents/MacOS/plugins`
    - On Linux, the folder may be at `/opt/IDA/plugins/`

`NOTE`
- On Windows, if you get an error message from IDA about "fail to load the dynamic library", then your machine may miss the VC++ runtime library. Fix that by downloading & installing it from https://www.microsoft.com/en-gb/download/details.aspx?id=40784
- On other \*nix platforms, the above error message means you do not have 32-bit Keystone installed yet. See [appendix section](#appendix-install-keystone-for-ida-pro) below for more instructions to fix this.


------------

### 3. Usage

- For a quick tutorial, see [TUTORIAL.md](TUTORIAL.md). For a complete description of all of the features of Keypatch, keep reading.

- To patch your binary, press hotkey `CTRL+ALT+K` inside IDA to open **Keypatch Patcher** dialog.
    - The original assembly, encode & instruction size will be displayed in 3 controls at the top part of the form.
    - Choose the syntax, type new assembly instruction in the `Assembly` box (you can use IDA symbols).
    - Keypatch would *automatically* update the encoding in the `Encode` box while you are typing, without waiting for `ENTER` keystroke.
        - Note that you can type IDA symbols, and the raw assembly will be displayed in the `Fixup` control.
    - Press `ENTER` or click `Patch` to overwrite the current instruction with the new code, then *automatically* advance to the the next instruction.
        - Note that when size of the new code is different from the original code, Keypatch can pad until the next instruction boundary with NOPs opcode, so the code flow is intact. Uncheck the choice `NOPs padding until next instruction boundary` if this is undesired.
        - By default, Keypatch appends the modified instruction with the information of the original code (before being patched). Uncheck the choice `Save original instructions in IDA comment` to disable this feature.
    - By default, the modification you made is only recorded in the IDA database. To apply these changes to the original binary (thus overwrite it), choose menu `Edit | Patch program | Apply patches to input file`.
<p align="center">
<img src="screenshots/keypatch_patcher.png" height="460" />
</p>

- To fill a range of code with an instruction, select the range, then either press hotkey `CTRL+ALT+K`, or choose menu `Edit | Keypatch | Fill Range`.
    - In the `Assembly` box, you can either enter assembly code, or raw hexcode. Some examples of acceptable raw hexcode are `90`, `aa bb`, `0xAA, 0xBB`.
<p align="center">
<img src="screenshots/keypatch_fillrange.png" height="460" />
</p>

- To revert (undo) the last patching, choose menu `Edit | Keypatch | Undo last patching`.

- To search for assembly instructions (without overwritting binary), open **Keypatch Search** from menu `Edit | Keypatch | Search`.
    - Choose the architecture, address, endian mode & syntax, then type assembly instructions in the `Assembly` box.
    - Keypatch would *automatically* update the encoding in the `Encode` box while you are typing, without waiting for `ENTER` keystroke.
    - When you click `Search` button, Keypatch would look for all the occurences of the instructions, and show the result in a new form.

<p align="center">
<img src="screenshots/keypatch_search.png" height="360" />
</p>

- To check for new version of Keypatch, choose menu `Edit | Keypatch | Check for update`.

- At any time, you can also access to all the above Keypatch functionalities just by right-click in IDA screen, and choose from the popup menu.

<p align="center">
<img src="screenshots/keypatch_menupopup.png" height="300" />
</p>

--------------

### 4. Contact

Email keystone.engine@gmail.com for any questions.

For future update of Keypatch, follow our Twitter [@keystone_engine](https://twitter.com/keystone_engine) for announcement.

----

### Appendix. Install Keystone for IDA Pro

We all know that before IDA 7.0, IDA Pro's Python is 32-bit itself, so it can only loads 32-bit libraries. For this reason, we have to build & install Keystone 32-bit. However, since IDA 7.0 supports both 32-bit & 64-bit, which means we also need to install a correct version of Keystone. This section details the steps towards that goal.

#### A1. Windows

##### For 32-bit users ( IDA <= 7.0 )

It is easiest to just download & install Python 2.7 module for Windows from [http://www.keystone-engine.org/download](http://www.keystone-engine.org/download). Be sure to get the 32-bit version, regardless of your Windows edition.

If you prefer to compile from source, just use MSVC 32-bit & follow the instructions in [Windows documentation](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-WINDOWS.md) to build `keystone.dll`. After that, install Python module as in [Python documentation](https://github.com/keystone-engine/keystone/blob/master/bindings/python/README.md). Then copy `keystone.dll` to the directory of Keystone Python module.

##### For 64-bit users (IDA >= 7.0 )

If you have installed a Python 2.7 (64-bit) from the install package of IDA, then you can just add them into your `%PATH%`, and just download & install the module from pip or the [website](http://www.keystone-engine.org/download). Be sure you are getting the 64-bit version.

We have not yet tested to compile it from source, but you are welcomed to use a MSVC 64-bit and following the simillar steps in the previous paragraph. It should work, but if not, just send a pull request.

#### A2. MacOS
The macOS python is universal binary, so does not need to discuss the situation(x86, x64).

Compiling dynamic library(libkeystone.dylib) depends on cmake and compiler(llvm clang, gcc).

Quick start steps:

Install the core & Python module of Keystone with the following command:

- install brew

  ```shell
  /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  ```

- install cmake

  ```shell
  brew install cmake
  ```

- install keystone-engine

  ```shell
  sudo pip install keystone-engine
  ```

  - Check Method ( Whether the installation is successful? ):

    - You enter this in the console of ida

      Normal result:

      ```python
      Python>print keystone
      <module 'keystone.keystone' from '/Applications/IDA Pro 7.0/ida64.app/Contents/MacOS/python/keystone/keystone.py'>

      Python>print keystone.arm_const
      <module 'keystone.arm_const' from '/Applications/IDA Pro 7.0/ida64.app/Contents/MacOS/python/keystone/arm_const.py'>
      ```
    - enter this in the  python standard console

      Normal result:

      ```python
      Python 2.7.13 (default, Jul 18 2017, 09:17:00)
      [GCC 4.2.1 Compatible Apple LLVM 8.1.0 (clang-802.0.42)] on darwin
      Type "help", "copyright", "credits" or "license" for more information.
      >>> import keystone
      >>> print keystone
      <module 'keystone' from '/usr/local/lib/python2.7/site-packages/keystone/__init__.pyc'>
      >>> print keystone.arm_const
      <module 'keystone.arm_const' from '/usr/local/lib/python2.7/site-packages/keystone/arm_const.pyc'>
      >>>
      ```


If there are cmake and compiler, then install only the core & Python module of Keystone with the following command:

```shell
$ sudo pip install keystone-engine
```

#### FAQ

1. Error "ImportError: No module named keystone"

In case IDA still complains "ImportError: No module named keystone" when Keypatch is loading, then do the following step to copy Keystone Python binding to IDA directory. (replace `6.8` with your actual IDA version)

```shell
$ sudo cp -r /Library/Python/2.7/site-packages/keystone /Applications/IDA\ Pro\ 6.8/idaq.app/Contents/MacOS/python
```

In addition, executable file rename "idaq" to "ida" in ida pro 7, so it is "ida.app/ida64.app".

```shell
cp -r /Library/Python/2.7/site-packages/keystone /Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS/python 
```

2. Error "ImportError: ERROR: fail to load the dynamic library"

  - If the result "sudo pip install keystone-engine" of no error, but did not generate dynamic library, then try to manually do.

    - Download keystone-engine, and extract this

      ```shell
      https://pypi.python.org/packages/9a/fc/ed0d3f46921bfaa612d9e8ce8313f99f4149ecf6635659510220c994cb72/keystone-engine-0.9.1-3.tar.gz
      ```

      - Or get the latest version from the link below.

        ```
        https://pypi.python.org/pypi/keystone-engine
        ```

    - Manual compile and install keystone-engine, see the log below. Note that libkeystone.dylib is universal binary.

      ```shell
      cd keystone-engine-0.9.1-3
      sudo python setup.py install
      ```

      - Normal log:

        ```shell
        > sudo python setup.py install

        running install
        running build
        running build_py
        creating build
        creating build/lib
        creating build/lib/keystone
        copying keystone/__init__.py -> build/lib/keystone
        ...
        copying keystone/x86_const.py -> build/lib/keystone
        running build_clib
        running custom_build_clib
        building 'keystone' library
        -- The C compiler identification is AppleClang 9.0.0.9000037
        -- The CXX compiler identification is AppleClang 9.0.0.9000037

        -- Check for working C compiler: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc
        -- Check for working C compiler: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc -- works

        -- Constructing LLVMBuild project information
        -- Targeting AArch64
        -- Targeting ARM
        ...
        -- Targeting X86
        -- Found PkgConfig: /usr/local/bin/pkg-config (found version "0.29.2")
        -- Configuring done
        CMake Warning (dev):
          Policy CMP0068 is not set: RPATH settings on macOS do not affect
          install_name.  Run "cmake --help-policy CMP0068" for policy details.  Use
          the cmake_policy command to set the policy and suppress this warning.

          For compatibility with older versions of CMake, the install_name fields for
          the following targets are still affected by RPATH settings:

           keystone

        This warning is for project developers.  Use -Wno-dev to suppress it.

        -- Generating done
        -- Build files have been written to: ~/Downloads/keystone-engine-0.9.1-3/src/build
        Scanning dependencies of target keystone
        [  0%] Building CXX object llvm/keystone/CMakeFiles/keystone.dir/__/lib/MC/ConstantPools.cpp.o
        ...
        [100%] Built target keystone
        running install_lib
        running install_data
        copying src/build/llvm/lib/libkeystone.dylib -> /usr/local/lib/python2.7/site-packages/keystone
        running install_egg_info
        Removing /usr/local/lib/python2.7/site-packages/keystone_engine-0.9.1_3-py2.7.egg-info
        Writing /usr/local/lib/python2.7/site-packages/keystone_engine-0.9.1_3-py2.7.egg-info
        ```
        ​

#### A3. Linux

##### For 32-bit users ( IDA <= 7.0 )

First of all, be sure that your machine already have Cmake installed. On Ubuntu, you can install Cmake with:

```
$ sudo apt-get install cmake
```

Then if your system is Linux 32-bit, you can install Keystone via `pip` as with MacOS above.

```
$ sudo pip install keystone-engine
```

In case you are on 64-bit Linux, you need to cross compile Keystone to 32-bit. Since version 0.9.1, Keystone supports `lib32` option to make this easy. After building the core, install Python module as in [Python documentation](https://github.com/keystone-engine/keystone/blob/master/bindings/python/README.md).

Note that to cross-compile on Linux, you need to install some multilib libraries. For example, on Ubuntu 14.04 64-bit, do this with:

    $ sudo apt-get install lib32stdc++-4.8-dev libc6-dev-i386

After having multilib dependencies, run the following commands in the source directory of Keystone.

```
$ mkdir build
$ cd build
$ ../make-share.sh lib32 lib_only
```

Then copy Python bindings to IDA's Python directory, together with disutils from your distro's Python to IDA's Python, like following. (Use your actual IDA directory instead)

```
$ sudo cp -r bindings/python/keystone /opt/IDAPro6.8/python/
$ sudo cp -r /usr/lib/python2.7/distutils /opt/IDAPro6.8/python/
```

Finally, copy the 32-bit libraries of Keystone to the Python directory of IDA Pro, like following.

```
$ sudo cp build/llvm/lib/libkeystone.so.* /opt/IDAPro6.8/python/keystone/
```

These complicated workarounds are necessary because IDA in Linux 64 bit doesn't use the system's Python.

Done? Now go back to [section 2](#2-install) & install Keypatch for IDA Pro. Enjoy!

##### For 64-bit users (IDA >= 7.0 )

Still waiting for brave warriors.
