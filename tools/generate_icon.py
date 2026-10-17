from pathlib import Path
r=Path(__file__).resolve().parents[1] / 'assets'
# Clipboard outline with two opposing arrows. Pixel-aligned at the 18-point template size.
paths=['M 6 4 L 4 4 L 4 21 L 20 21 L 20 4 L 18 4', 'M 8 3 L 16 3 L 16 7 L 8 7 Z', 'M 7 11 L 17 11 L 14 8', 'M 17 16 L 7 16 L 10 19']
s='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'+''.join('<path d="'+p+'"/>' for p in paths)+'</svg>\n'
(r/'status-template.svg').write_text(s)
commands=['q','1 0 0 -1 0 24 cm','0 G','1.7 w','1 J','1 j']
for path in paths:
 t=path.split();i=0
 while i<len(t):
  op=t[i];i+=1
  if op=='Z': commands.append('h');continue
  x,y=t[i:i+2];i+=2;commands.append(f'{x} {y} '+('m' if op=='M' else 'l'))
 commands.append('S')
commands.append('Q');stream='\n'.join(commands).encode()
objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 24 24] /Resources << >> /Contents 4 0 R >>',b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream']
b=bytearray(b'%PDF-1.4\n');offset=[0]
for n,obj in enumerate(objects,1):offset.append(len(b));b.extend(f'{n} 0 obj\n'.encode()+obj+b'\nendobj\n')
x=len(b);b.extend(b'xref\n0 5\n0000000000 65535 f \n')
for off in offset[1:]:b.extend(f'{off:010} 00000 n \n'.encode())
b.extend(f'trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n'.encode());(r/'status-template.pdf').write_bytes(b)
print('Template SVG and vector PDF generated:',len(s.encode()),len(b),'bytes')
