# GUIDED-RESTORE-RESUME-RELEASE stage 1: the shared guided setup (guest/guided.sh); the other stages
# are host-driven Menu dialogues (host/guided.py). The probe powers A off.
. /acceptance/guided.sh

stage_1() { guided_setup poweroff; }
