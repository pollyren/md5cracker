#!/bin/bash

#SBATCH --mail-user=${SBATCH_EMAIL}
#SBATCH --mail-type=ALL
#SBATCH --output=${SBATCH_OUTPUT_DIR}/%j.%N.stdout
#SBATCH --error=${SBATCH_OUTPUT_DIR}/%j.%N.stderr
#SBATCH --chdir=${SBATCH_ROOT_DIR}
#SBATCH --partition=${SBATCH_PARTITION}
#SBATCH --gres=gpu:1
#SBATCH --job-name=proj3_gpu

export PATH=$PATH:/usr/local/cuda/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/cuda/lib

if [[ "$1" == "-u" ]]; then
    src/cracker -n $2 -r -t -u
else
    src/cracker -n $1 -r -t
fi