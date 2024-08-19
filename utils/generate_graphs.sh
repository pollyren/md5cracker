#!/bin/bash

#SBATCH --mail-user=${SBATCH_EMAIL}
#SBATCH --mail-type=ALL
#SBATCH --output=${SBATCH_OUTPUT_DIR}/%j.%N.stdout
#SBATCH --error=${SBATCH_OUTPUT_DIR}/%j.%N.stderr
#SBATCH --chdir=${SBATCH_SRC_DIR}
#SBATCH --partition=${SBATCH_PARTITION}
#SBATCH --gres=gpu:1
#SBATCH --job-name=proj3_graphs

export PATH=$PATH:/usr/local/cuda/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/cuda/lib

make clean
make
cd ..

mkdir results
rm -f results/times.csv
rm -f results/times_unif.csv

cd utils

gpu_dependency=""
seq_dependency=""
gpu_dependency_u=""
seq_dependency_u=""

for num_passwords in {1..10}
do
    for i in {1..8}
    do
        if [ -z "$gpu_dependency" ]; then
            gpu_job_id=$(sbatch --parsable run_gpu.sh $num_passwords)
        else
            gpu_job_id=$(sbatch --parsable --dependency=afterok:$gpu_dependency run_gpu.sh $num_passwords)
        fi
        gpu_dependency=$gpu_job_id
    done

    for i in {1..8}
    do
        if [ -z "$seq_dependency" ]; then
            seq_job_id=$(sbatch --parsable run_seq.sh $num_passwords)
        else
            seq_job_id=$(sbatch --parsable --dependency=afterok:$seq_dependency run_seq.sh $num_passwords)
        fi
        seq_dependency=$seq_job_id
    done

    for i in {1..10}
    do
        if [ -z "$gpu_dependency_u" ]; then
            gpu_job_id=$(sbatch --parsable run_gpu.sh -u $num_passwords)
        else
            gpu_job_id=$(sbatch --parsable --dependency=afterok:$gpu_dependency_u run_gpu.sh -u $num_passwords)
        fi
        gpu_dependency_u=$gpu_job_id
    done

    for i in {1..10}
    do
        if [ -z "$seq_dependency_u" ]; then
            seq_job_id=$(sbatch --parsable run_seq.sh -u $num_passwords)
        else
            seq_job_id=$(sbatch --parsable --dependency=afterok:$seq_dependency_u run_seq.sh -u $num_passwords)
        fi
        seq_dependency_u=$seq_job_id
    done
done