import os
import pandas as pd

def consolidate_users(directory_path, output_file):
    # List to store all users
    all_users = []

    # Iterate through each file in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith('.xlsx'):
            file_path = os.path.join(directory_path, filename)

            # Read the 'User' tab from the Excel file
            try:
                df = pd.read_excel(file_path, sheet_name='User')

                # Assuming the users are in column A
                users = df.iloc[:, 0].tolist()
                all_users.extend(users)
            except Exception as e:
                print(f"Error reading {filename}: {e}")

    # Remove duplicates and create a DataFrame
    unique_users = list(set(all_users))
    users_df = pd.DataFrame(unique_users, columns=['Users'])

    # Write to a new Excel file
    output_path = os.path.join(directory_path, output_file)
    users_df.to_excel(output_path, index=False)
    print(f"All users consolidated into {output_path}")

# Set the directory path and output file name
directory_path = r"C:\Users\craig\Files"
output_file = "all_users.xlsx"

# Run the function
consolidate_users(directory_path, output_file)
