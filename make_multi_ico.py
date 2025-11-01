from PIL import Image

src = r'C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\pcfix_icon.ico'
dst = r'C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\pcfix_icon_multi.ico'

im = Image.open(src)
if im.mode != 'RGBA':
    im = im.convert('RGBA')

sizes = [(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)]
im.save(dst, sizes=sizes)
print('Wrote', dst)
