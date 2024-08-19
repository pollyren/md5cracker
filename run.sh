#!/bin/bash

#SBATCH --mail-user=${SBATCH_EMAIL}
#SBATCH --mail-type=ALL
#SBATCH --output=${SBATCH_OUTPUT_DIR}/%j.%N.stdout
#SBATCH --error=${SBATCH_OUTPUT_DIR}/%j.%N.stderr
#SBATCH --chdir=${SBATCH_SRC_DIR}
#SBATCH --partition=${SBATCH_PARTITION}
#SBATCH --gres=gpu:1
#SBATCH --job-name=proj3_job

export PATH=$PATH:/usr/local/cuda/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/cuda/lib

make clean
make

cd ..

U_VALUE=""
N_VALUE=""
CRACKER_ARGS=()

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u) U_VALUE="$2"; CRACKER_ARGS+=("-u"); shift 2 ;;
        -n) N_VALUE="$2"; CRACKER_ARGS+=("-n" "$2"); shift 2 ;;
        *) CRACKER_ARGS+=("$1"); shift ;;
    esac
done

GENERATE_PASSWORDS_ARGS="$N_VALUE"
if [[ -n "$U_VALUE" ]]; then
    GENERATE_PASSWORDS_ARGS="-u $U_VALUE $GENERATE_PASSWORDS_ARGS"
fi

cd utils
python generate_passwords.py $GENERATE_PASSWORDS_ARGS
echo $GENERATE_PASSWORDS_ARGS

cd ..
src/cracker "${CRACKER_ARGS[@]}"