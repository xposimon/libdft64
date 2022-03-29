'''
Date: 2022-03-29 18:27:24
LastEditors: zx Zhou
LastEditTime: 2022-03-29 19:00:14
FilePath: /libdft64/tools/scripts/fuzz_state.py
'''

from info_collect.collector import *


info_dir = os.path.join(os.path.dirname(__file__), "./info/")

function_mapping = {
    "fuzz_cfg"  :  cfg_generate,
    "cmp_hook"  :  cmp_analysis
}

for fname, func in function_mapping.items():
    with open(os.path.join(info_dir, fname+".info")) as f:
        info_content = f.read()
    func(info_content)
