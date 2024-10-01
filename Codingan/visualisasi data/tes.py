import matplotlib.pyplot as plt
import pandas as pd

# Baca data dari file CSV
data = pd.read_csv('data.csv')

# Buat grafik garis
plt.figure(figsize=(8, 8))
plt.plot(data['Tahun'], data['Nilai'])
plt.xlabel('Tahun')
plt.ylabel('Nilai')
plt.title('Grafik Garis')
plt.grid(True)
plt.show()