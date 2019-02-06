# tanker_init() must be called once and before any session is created,
# so do it here at import time

import _tanker

_tanker.lib.tanker_init()
