"""The former plugin's task-name oracle, using the real loader helper/kernel."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


NATIVE = Path(__file__).resolve().parent


class GuestCommTest(unittest.TestCase):
    def test_guest_comm_uses_target_basename_and_linux_limit(self):
        self.assertIsNotNone(shutil.which("cc"), "required fixture compiler")
        with tempfile.TemporaryDirectory() as scratch:
            scratch = Path(scratch)
            source = scratch / "guest-comm.c"
            source.write_text(r'''
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include "loader/guest_comm.h"
int main(int argc, char **argv) {
  char name[16], actual[16];
  if (argc != 2 || !sbr_guest_comm_from_program(argv[1], name)) return 2;
  if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0) return 3;
  if (prctl(PR_GET_NAME, actual, 0, 0, 0) != 0) return 4;
  if (memcmp(actual, name, sizeof(name)) != 0) return 5;
  return fwrite(actual, 1, strlen(actual), stdout) == strlen(actual) ? 0 : 6;
}
''')
            executable = scratch / "guest-comm"
            env = dict(os.environ)
            env.update(NIX_DONT_SET_RPATH="1", NIX_DONT_SET_RPATH_FOR_TARGET="1",
                       NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu="1")
            includes = NATIVE / "../../experimental/reverie-sabre/vendor/sabre/includes"
            built = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    "-I", str(includes.resolve(strict=True)), str(source),
                                    "-o", str(executable)], env=env, capture_output=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            # Both original exact-byte assertions, with the actual kernel name
            # checked in each disposable native fixture process as well.
            for program, expected in [("/usr/bin/bash", b"bash"),
                                      ("abcdefghijklmnop", b"abcdefghijklmno")]:
                with self.subTest(program=program):
                    result = subprocess.run([str(executable), program], env=env,
                                            capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
