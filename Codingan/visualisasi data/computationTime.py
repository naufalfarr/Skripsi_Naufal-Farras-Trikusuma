import matplotlib.pyplot as plt
import numpy as np

algorithms = ['ChaCha20', 'Snow-V',  'Clefia', 'AES-CBC']
time_10kb = [10994.4, 11257.9, 92659.3, 115393.9]
time_5kb = [5662, 5663.9, 46563.1, 58884.8]  

bar_width = 0.4

# Posisi untuk bar 5KB dan 10KB
index = np.arange(len(algorithms))

# Create the figure and axes
plt.figure(figsize=(10, 6))

# Bar chart untuk 5KB dan 10KB dengan warna yang lebih nyaman
plt.bar(index, time_5kb, bar_width, label='5KB', color='#8BC34A') 
plt.bar(index + bar_width, time_10kb, bar_width, label='10KB', color='#2f84f5')  

# Add labels and title
plt.xlabel('Algoritma Enkripsi', fontsize=14)
plt.ylabel('Waktu Komputasi Dalam Mikrosekon (μs)', fontsize=14)
plt.ylim(0, 150000)  # Adjusted to fit both sets of bars

# Show the values on top of the bars
for i, time in enumerate(time_5kb):
    plt.text(i, time + 10, f"{time} μs", ha='center', fontsize=9)
for i, time in enumerate(time_10kb):
    plt.text(i + bar_width, time + 10, f"{time} μs", ha='center', fontsize=9)

# Add legend
plt.legend()

# Display the plot
plt.xticks(index + bar_width / 2, algorithms, fontsize=12)  # Adjust the font size of x-ticks
plt.yticks(fontsize=12)  # Adjust the font size of y-ticks
plt.show()
