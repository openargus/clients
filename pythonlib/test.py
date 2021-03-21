from __future__ import print_function, division

import argusWgan as aw
import numpy as np

y_true = np.random.randint(0, 2, size=(2, 3))
y_pred = np.random.random(size=(2, 3))
s = aw.argus_critic(y_true, y_pred)
