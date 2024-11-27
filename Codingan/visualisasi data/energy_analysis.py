import matplotlib.pyplot as plt
import numpy as np

# Data untuk energi rata-rata (dalam Joules) untuk masing-masing algoritma dan ukuran data
algorithms = ['ChaCha20', 'Snow-V', 'Clefia', 'AES-CBC']
energy_5kb = [0.003807, 0.003819, 0.024201 , 0.028087 ]
energy_10kb = [0.006578, 0.006689, 0.046383, 0.049434 ]

bar_width = 0.4

# Posisi untuk bar 5KB dan 10KB
index = np.arange(len(algorithms))

# Create the figure and axes
plt.figure(figsize=(10, 6))

plt.bar(index, energy_5kb, bar_width, label='5KB', color='#FF7043')  
plt.bar(index + bar_width, energy_10kb, bar_width, label='10KB', color='#42A5F5')

# Add labels and title
plt.xlabel('Algoritma Enkripsi', fontsize=14)
plt.ylabel('Konsumsi Energi (Joules)', fontsize=14)
plt.ylim(0, 0.06)  # Adjusted to fit both sets of bars

# Show the values on top of the bars
for i, energy in enumerate(energy_5kb):
    plt.text(i, energy + 0.0001, f"{energy:.6f} J", ha='center', fontsize=9)
for i, energy in enumerate(energy_10kb):
    plt.text(i + bar_width, energy + 0.0001, f"{energy:.6f} J", ha='center', fontsize=9)

# Add legend
plt.legend()

# Display the plot
plt.xticks(index + bar_width / 2, algorithms, fontsize=12)  # Adjust the font size of x-ticks
plt.yticks(fontsize=12)  # Adjust the font size of y-ticks
# plt.title('Perbandingan Konsumsi Energi Berdasarkan Data Uji', fontsize=16)
plt.show()
