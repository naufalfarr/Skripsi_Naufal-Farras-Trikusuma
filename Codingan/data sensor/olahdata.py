import csv

# Baca data dari file CSV yang ada
input_file = 'data_dht22.csv'
output_file = 'output.csv'

with open(input_file, mode='r', newline='') as csvfile:
    reader = csv.reader(csvfile)
    
    # Menyimpan hasil dalam format yang diinginkan
    data = [f'{",".join(row)}' for row in reader]

# Tulis data baru ke file CSV
with open(output_file, mode='w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for row in data:
        writer.writerow([row])

print(f"Data telah berhasil diubah dan disimpan ke {output_file}.")
