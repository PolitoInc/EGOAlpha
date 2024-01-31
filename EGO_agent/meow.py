import os

def remove_print_statements(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r+') as f:
                    lines = f.readlines()
                    f.seek(0)
                    for line in lines:
                            f.write(line)
                    f.truncate()

# Call the function with the directory path
remove_print_statements('/mnt/e/tools/0_Secret_lab/EGO_old/EGO_Release/EGO_agent')
