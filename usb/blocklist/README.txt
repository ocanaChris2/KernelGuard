Deny lists used by the live scan.  Both files are optional; edit them on the stick.

  sha256.deny     one SHA-256 (hex) per line, for Linux modules or Windows .sys drivers,
                  e.g. taken from a vulnerable-driver list such as loldrivers.io
  modules.deny    Linux module entries as printed by `kgmon modid`: NAME or NAME@SRCVERSION
                  (the same syntax as the kernelguard mod_deny= parameter)

'#' starts a comment; anything after the first word on a line is ignored.
No entries ship here: the lists are yours to maintain.  A match becomes a FINDING line in the report.
