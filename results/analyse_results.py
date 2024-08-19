import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import argparse

def plot(times_avg, title, filename, both):
    times_pivot = times_avg.pivot(index='num_passwords', columns='type', values='time')

    times_pivot.plot(kind='bar', figsize=(7, 5))

    plt.title(title)
    plt.xlabel('number of passwords')
    plt.ylabel('average computation time (s)')
    plt.xticks(rotation=0)
    plt.grid(True, axis='y')

    legend = plt.legend()
    legend.get_texts()[0].set_text('GPU')
    if both:
        legend.get_texts()[1].set_text('Sequential')

    plt.savefig(filename)

def main():
    parser = argparse.ArgumentParser(description='plot timing results for cracker')
    parser.add_argument('-u', '--uniform', action='store_true')
    args = parser.parse_args()

    print('uniform is', args.uniform)
    
    title = '{} runtimes by number of passwords ({})'

    file = f'times{"_unif" if args.uniform else ""}'
    times = pd.read_csv(f'{file}.csv', names=['num_passwords', 'type', 'time'])
    
    times_avg = times.groupby(['num_passwords', 'type']).aggregate(np.mean).reset_index()
    plot(times_avg, title.format('computational', 'length=4' if args.uniform else 'length ~ N(3.5, 1)'), f'{file}.png', True)

    gpu_times_avg = times_avg[times_avg['type'] != 'seq']
    plot(gpu_times_avg, title.format('GPU', 'length=4' if args.uniform else 'length ~ N(3.5, 1)'), f'{file}_gpu.png', False)

if __name__ == '__main__':
    main()