from PIL import Image
import os

# Path to your PNG file
input_file = "Logo.png"
output_file = "Logo.ico"

# Create icon with multiple resolutions
img = Image.open(input_file)
# Convert to RGBA if not already
if img.mode != 'RGBA':

    img = img.convert('RGBA')

# Create a list of images with different sizes
icon_sizes = [(256, 256)]
img.save(output_file, format='ICO', sizes=icon_sizes)

print(f"Created icon file at {output_file}")