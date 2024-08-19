#include <cuda_runtime.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
extern "C" {
    #include "md5.cuh"
}

#define DEBUG                       0

#define HASH_LENGTH                 16
#define MIN_PASSWORD_LENGTH         1
#define MAX_PASSWORD_LENGTH         8
#define DEFAULT_PW_SPACE_START      0ULL

#define THREADS_PER_BLOCK           256
#define THREAD_COARSENING_FACTOR    4

const char CHARSET_H[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=<>?/";
__constant__ char CHARSET_D[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=<>?/";
#define CHARSET_SIZE                (sizeof(CHARSET_H) - 1)

/* Macro to check for errors after CUDA functions */
#define CUDA_CHECK(call)                                                    \
{                                                                           \
   const cudaError_t error = call;                                          \
   if (error != cudaSuccess)                                                \
   {                                                                        \
       printf("Error: %s:%d, ", __FILE__, __LINE__);                        \
       printf("code:%d, reason: %s\n", error, cudaGetErrorString(error));   \
       exit(1);                                                             \
   }                                                                        \
}

void print_usage_details(char *program) {
    fprintf(stderr, "usage: %s [-n <num_passwords>] [-s] [-u] [-r] [-t] [-p]\n", program);
    fprintf(stderr, "\nAvailable options:\n");
    fprintf(stderr, "  -n <num_passwords>    number of passwords to process (default=10)\n");
    fprintf(stderr, "  -s                    run sequential version\n");
    fprintf(stderr, "  -u                    read from uniform length passwords file\n");
    fprintf(stderr, "  -r                    generate report with cracking time per password\n");
    fprintf(stderr, "  -t                    enable timing, for timing test purposes\n");
    fprintf(stderr, "  -p                    track cracking progress, for debugging purposes\n");
}

void parse_args(int argc, char *argv[], bool *run_sequential, int *num_passwords, bool *uniform, bool *generate_report, bool *enable_timing, bool *track_progress) {
    bool s = false, u = false, r = false, t = false, p = false;
    int n = 10;

    int opt;
    while ((opt = getopt(argc, argv, "surtpn:")) != -1) {
        switch (opt) {
            case 's':
                s = true;
                break;
            case 'u':
                u = true;
                break;
            case 'r':
                r = true;
                break;
            case 't':
                t = true;
                break;
            case 'p':
                p = true;
                break;
            case 'n':
                n = atoi(optarg);
                break;
            default:
                print_usage_details(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    *run_sequential = s;
    *uniform = u;
    *num_passwords = n;
    *generate_report = r;
    *enable_timing = t;
    *track_progress = p;
}

void parse_files(int num_passwords, char **hashes, char **ptxts, bool uniform) {
    char hashed[50];
    char plain[50];

    sprintf(hashed, "inputs/%d%s_hashed.txt", num_passwords, uniform ? "u" : "");
    sprintf(plain, "inputs/%d%s_plain.txt", num_passwords, uniform ? "u" : "");

    FILE *f_hashed = fopen(hashed, "r");
    FILE *f_plain = fopen(plain, "r");
    if (!f_hashed || !f_plain) {
        fprintf(stderr, "parse_file: unable to open file %s\n", !f_hashed ? hashed : plain);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_passwords; i++) {
        cudaMallocManaged(&hashes[i], (2*HASH_LENGTH + 1) * sizeof(char));
        cudaMallocManaged(&ptxts[i], (MAX_PASSWORD_LENGTH + 1) * sizeof(char));
        fscanf(f_hashed, "%s", hashes[i]);
        fscanf(f_plain, "%s", ptxts[i]);
    }

    fclose(f_hashed);
    fclose(f_plain);
}

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

void create_report(char *report_name, int num_passwords, char **hashes, char **cracks, float *times, float total_time) {
    FILE *report = fopen(report_name, "w");
    fprintf(report, "%-36s\t%-10s\t%-10s\n", "hash", "password", "time");
    for (int i = 0; i < num_passwords; i++) {
        fprintf(report, "%-36s\t%-10s\t%-10.5f\n", hashes[i], cracks[i], times[i]/1000.0);
    }
    fprintf(report, "\n===total time:\t%f===", total_time / 1000.0);
    fprintf(report, "\n===avg time:\t%f===\n", total_time / (1000.0*num_passwords));
    fclose(report);
}

/*************************** SHARED COMPUTATION FUNCTIONS ***************************/
__host__ __device__ unsigned long long compute_total_combinations(int len) {
    unsigned long long total_combinations = 1;
    for (int i = 0; i < len; i++) {
        total_combinations *= CHARSET_SIZE;
    }
    return total_combinations;
}

__host__ __device__ void hexdigest(unsigned char *input, char *output) {
    const char hex[] = "0123456789abcdef";
    unsigned char byte;

    for (int i = 0; i < HASH_LENGTH; i++) {
        byte = input[i];
        output[i*2] = hex[(byte >> 4) & 0xf];
        output[i*2 + 1] = hex[byte & 0xf];
    }
    output[HASH_LENGTH * 2] = 0;
}

__host__ __device__ void md5_digest(char *input, int len, char *output) {
    unsigned char tmp[HASH_LENGTH + 1];

    md5(input, len, tmp);
    hexdigest(tmp, output);
}

__host__ __device__ bool try_password(char *guess, char *actual_hash) {
    char guess_hash[HASH_LENGTH*2 + 1];

    int len = 0;
    while (guess[len]) len++;

    md5_digest(guess, len, guess_hash);

    for (int i = 0; i < HASH_LENGTH*2; i++) {
        if (guess_hash[i] != actual_hash[i]) return false;
    }

    return true;
}

/*************************** SEQUENTIAL IMPLEMENTATION ***************************/
char *crack_one_password_seq(char *hash, bool track_progress) {
    char guess[MAX_PASSWORD_LENGTH + 1];
    unsigned long long total_combinations, x;

    for (int len = MIN_PASSWORD_LENGTH; len <= MAX_PASSWORD_LENGTH; len++) {
        total_combinations = compute_total_combinations(len);

        if (track_progress) {
            printf("\ttrying passwords of length %d\n", len); fflush(stdout);
        }

        for (unsigned long long combo = 0; combo < total_combinations; combo++) {
            x = combo;
            for (int i = 0; i < len; i++) {
                guess[i] = CHARSET_H[x % CHARSET_SIZE];
                x /= CHARSET_SIZE;
            }
            guess[len] = 0;

            if (try_password(guess, hash)) {
                return strdup(guess);
            }
        }
    }

    return NULL;
}

char **crack_passwords_seq(char **hashes, int num_passwords, bool generate_report, bool track_progress) {
    char **cracks = (char **)malloc(num_passwords * sizeof(char *));
    float *times = (float *)malloc(num_passwords * sizeof(float));

    float start_time, end_time;
    for (int i = 0; i < num_passwords; i++) {
        if (generate_report)
            start_time = get_time_ms();

        if (track_progress) {
            printf("===cracking %s...\n", hashes[i]); fflush(stdout);
        }

        cracks[i] = crack_one_password_seq(hashes[i], track_progress);

        if (track_progress) {
            printf(">>>%s done\n", cracks[i]); fflush(stdout);
        }

        if (generate_report) {
            end_time = get_time_ms();
            times[i] = end_time - start_time;
        }
    }

    if (generate_report) {
        float total_time = 0.0f;
        for (int i = 0; i < num_passwords; i++) {
            total_time += times[i];
        }

        char report_name[32];
        sprintf(report_name, "crack_report_seq_%d.txt", num_passwords);
        create_report(report_name, num_passwords, hashes, cracks, times, total_time);
    }

    return cracks;
}

/*************************** GPU IMPLEMENTATION ***************************/
__global__ void crack_one_password_gpu(char *hash, char *final_result, int len, unsigned long long total_combinations, unsigned long long password_space_start) {
    unsigned long long idx = (blockIdx.x * blockDim.x + threadIdx.x) * THREAD_COARSENING_FACTOR + password_space_start;
    char guess[MAX_PASSWORD_LENGTH + 1];

    unsigned long long x;
    for (int coarse_idx = 0; coarse_idx < THREAD_COARSENING_FACTOR; coarse_idx++) {
        if (idx >= total_combinations || final_result[0]) return;

        x = idx++;
        for (int i = 0; i < len; i++) {
            guess[i] = CHARSET_D[x % CHARSET_SIZE];
            x /= CHARSET_SIZE;
        }
        guess[len] = 0;

        if (try_password(guess, hash)) {
            for (int i = 0; i < MAX_PASSWORD_LENGTH + 1; ++i) {
                final_result[i] = guess[i];
                if (guess[i] == 0) break;
            }
            return;
        }
    }
}

__global__ void add_times_block(float *times, float *partial_sums, int num_passwords) {
    extern __shared__ float shared_data[];

    int index = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;

    if (index >= num_passwords) return;

    float sum = 0.0f;
    for (int i = index; i < num_passwords; i += blockDim.x * gridDim.x) {
        sum += times[i];
    }
    shared_data[tid] = sum;
    __syncthreads();

    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            shared_data[tid] += shared_data[tid + stride];
        }
        __syncthreads();
    }

    if (tid == 0) {
        partial_sums[blockIdx.x] = shared_data[0];
    }
}

__global__ void add_times_final(float *partial_sums, float *total_time, int num_blocks) {
    extern __shared__ float shared_data[];

    int tid = threadIdx.x;

    if (tid >= num_blocks) return;

    float sum = 0.0f;
    for (int i = tid; i < num_blocks; i += blockDim.x) {
        sum += partial_sums[i];
    }
    shared_data[tid] = sum;
    __syncthreads();

    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            shared_data[tid] += shared_data[tid + stride];
        }
        __syncthreads();
    }

    if (tid == 0) {
        *total_time = shared_data[0];
    }
}

char **crack_passwords_gpu(char **hashes, int num_passwords, bool generate_report, bool track_progress) {
    char **cracks;
    cudaMallocManaged(&cracks, num_passwords * sizeof(char *));

    unsigned long long total_combinations, blocks_per_grid;
    unsigned long long total_work = THREADS_PER_BLOCK * THREAD_COARSENING_FACTOR;
    unsigned long long max_blocks = (1ULL << 31) - 1;

    char *final_result;
    CUDA_CHECK(cudaMallocManaged(&final_result, (MAX_PASSWORD_LENGTH + 1) * sizeof(char)));

    float *times = NULL, *partial_sums = NULL;
    if (generate_report) {
        CUDA_CHECK(cudaMallocManaged(&times, num_passwords * sizeof(float)));
    }

    int num_streams;
    unsigned long long password_space_start, combos_per_stream;
    cudaStream_t *streams;
    cudaEvent_t start, stop;
    for (int i = 0; i < num_passwords; i++) {
        if (generate_report) {
            cudaEventCreate(&start);
            cudaEventCreate(&stop);
            cudaEventRecord(start);
        }

        final_result[0] = 0;

        for (int len = MIN_PASSWORD_LENGTH; len <= MAX_PASSWORD_LENGTH; len++) {
            total_combinations = compute_total_combinations(len);
            blocks_per_grid = (total_combinations + total_work - 1) / total_work;

            num_streams = (blocks_per_grid + max_blocks - 1) / max_blocks;

            if (num_streams == 1) {
                crack_one_password_gpu<<<blocks_per_grid, THREADS_PER_BLOCK>>>(
                    hashes[i], final_result, len, total_combinations, DEFAULT_PW_SPACE_START
                );
                CUDA_CHECK(cudaDeviceSynchronize());

                if (final_result[0]) {
                    cracks[i] = strdup(final_result);
                    break;
                }
            } else {
                streams = (cudaStream_t *)malloc(num_streams * sizeof(cudaStream_t));
                for (int j = 0; j < num_streams; j++) {
                    CUDA_CHECK(cudaStreamCreate(&streams[j]));
                }

                combos_per_stream = (total_combinations + num_streams - 1) / num_streams;

                for (int j = 0; j < num_streams; j++) {
                    password_space_start = j * combos_per_stream;

                    crack_one_password_gpu<<<max_blocks, THREADS_PER_BLOCK, 0, streams[j]>>>(
                        hashes[i], final_result, len, total_combinations, password_space_start
                    );
                    CUDA_CHECK(cudaGetLastError());
                }

                for (int j = 0; j < num_streams; j++) {
                    CUDA_CHECK(cudaStreamSynchronize(streams[j]));
                    if (final_result[0]) {
                        cracks[i] = strdup(final_result);
                        break;
                    }
                }

                for (int j = 0; j < num_streams; j++) {
                    CUDA_CHECK(cudaStreamDestroy(streams[j]));
                }
                free(streams);
            }
        }

        if (generate_report) {
            cudaEventRecord(stop);
            cudaEventSynchronize(stop);
            cudaEventElapsedTime(&times[i], start, stop);
            cudaEventDestroy(start);
            cudaEventDestroy(stop);
        }
    }

    cudaFree(final_result);

    if (generate_report) {
        float *total_time;
        CUDA_CHECK(cudaMallocManaged(&total_time, sizeof(float)));

        int password_blocks = (num_passwords + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
        CUDA_CHECK(cudaMalloc(&partial_sums, password_blocks * sizeof(float)));

        add_times_block<<<password_blocks, THREADS_PER_BLOCK, THREADS_PER_BLOCK * sizeof(float)>>>(times, partial_sums, num_passwords);
        CUDA_CHECK(cudaDeviceSynchronize());

        add_times_final<<<1, THREADS_PER_BLOCK, THREADS_PER_BLOCK * sizeof(float)>>>(partial_sums, total_time, password_blocks);
        CUDA_CHECK(cudaDeviceSynchronize());

        char report_name[32];
        sprintf(report_name, "crack_report_gpu_%d.txt", num_passwords);
        create_report(report_name, num_passwords, hashes, cracks, times, *total_time);

        cudaFree(times);
        cudaFree(partial_sums);
    }

    return cracks;
}

/*************************** VERIFICATION ***************************/
bool check_cracks_seq(char **cracked, char **ptxts, int num_passwords) {
    for (int i = 0; i < num_passwords; i++) {
        if (strcmp(cracked[i], ptxts[i])) return false;
    }
    return true;
}

__global__ void check_cracks_gpu(char **cracked, char **ptxts, int num_passwords, bool *result) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_passwords) return;
    if (cracked[idx] != ptxts[idx]) *result = false;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage_details(argv[0]);
        exit(EXIT_FAILURE);
    }

    bool run_sequential, uniform, generate_report, enable_timing, track_progress;
    int num_passwords;

    parse_args(argc, argv, &run_sequential, &num_passwords, &uniform, &generate_report, &enable_timing, &track_progress);

    char **hashes, **ptxts;
    cudaMallocManaged(&hashes, num_passwords * sizeof(char *));
    cudaMallocManaged(&ptxts, num_passwords * sizeof(char *));

    parse_files(num_passwords, hashes, ptxts, uniform);

    double start_time = get_time_ms();
    char **recovered = run_sequential 
                            ? crack_passwords_seq(hashes, num_passwords, generate_report, track_progress)
                            : crack_passwords_gpu(hashes, num_passwords, generate_report, track_progress);
    double end_time = get_time_ms();

    double elapsed_time = end_time - start_time;

    if (enable_timing) {
        FILE *time_file = fopen(uniform ? "results/times_unif.csv" : "results/times.csv", "a");
        fprintf(time_file, "%d,%s,%lf\n", num_passwords, run_sequential ? "seq" : "gpu", elapsed_time / 1000);
        fclose(time_file);
    }

    bool *result;
    CUDA_CHECK(cudaMallocManaged(&result, sizeof(bool)));
    *result = true;

    if (run_sequential) {
        *result = check_cracks_seq(recovered, ptxts, num_passwords);
    } else {
        int blocks_per_grid = (num_passwords + THREADS_PER_BLOCK-1) / THREADS_PER_BLOCK;
        check_cracks_gpu<<<blocks_per_grid, THREADS_PER_BLOCK>>>(recovered, ptxts, num_passwords, result);
        CUDA_CHECK(cudaDeviceSynchronize());
    }
    assert(result);

    char recovered_name[20];
    sprintf(recovered_name, "%d%s_recovered.txt", num_passwords, uniform ? "u" : "");

    FILE *cracks_file = fopen(recovered_name, "w");
    for (int i = 0; i < num_passwords; i++) {
        fprintf(cracks_file, "%s\n", recovered[i]);
    }
    fclose(cracks_file);

    for (int i = 0; i < num_passwords; i++) {
        cudaFree(hashes[i]);
        cudaFree(ptxts[i]);
    }
    cudaFree(hashes);
    cudaFree(ptxts);

    return 0;
}