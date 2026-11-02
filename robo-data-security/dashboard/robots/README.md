# Robot renders

Pictures of the robot shown in the dashboard banner. They are renders of the official robot models shipped with
[NVIDIA/soma-retargeter](https://github.com/NVIDIA/soma-retargeter) (Apache-2.0 code; the robot assets keep their makers' licenses):

| File | Robot | Model | License |
|---|---|---|---|
| `x2-ultra.png` | AgiBot X2 Ultra | `assets/robotics/agibot/x2/desc/agibot_x2ultra.urdf` | Mulan PSL v2 (`LICENSE-agibot.txt`) |
| `a3.png` | AgiBot A3 | `assets/robotics/agibot/a3/desc/agibot-a3t3.urdf` | Mulan PSL v2 (`LICENSE-agibot.txt`) |
| `g1.png` | Unitree G1 | `assets/robotics/unitree/g1/desc/mjcf/g1_29dof_rev_1_0.xml` | BSD-3-Clause (`LICENSE-unitree.txt`) |

Made with `tools/render_robots.py` (MuJoCo for the pose, a numpy/PIL software rasteriser, grey shading on a transparent background, so it works in both themes).
The renders are a model at its default pose, not photographs.
