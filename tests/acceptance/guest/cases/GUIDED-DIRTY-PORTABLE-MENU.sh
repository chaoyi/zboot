# GUIDED-DIRTY-PORTABLE-MENU stage 1: the shared guided setup (guest/guided.sh);
# the probe leaves A running so the host cuts it with both pools writable.
. /acceptance/guided.sh

stage_1() { guided_setup stay; }
