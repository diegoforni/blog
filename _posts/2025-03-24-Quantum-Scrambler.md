---
title: PicoCTF Quantum Scrambler Writeup
author: Diego Forni
date: 2025-03-24 14:10:00 +0800
categories: [CTF]
tags: [CTF, Writeup, Reverse Engineering ,PicoCTF, Medium]
render_with_liquid: false
---

Here you will see my detailed approach to the Challenge Quantum Scramble from PicoCTF, this is not meant to be the perfect solution, just how I thought this problem.

## Understanding the problem
The first step is to identify what useful information we have:
1. Source code
2. Ncat Command
* nc verbal-sleep.picoctf.net 57273
3. Hints

I will first focus on the source code.
## Source code analysis
In the code, we have 3 relevant functions. 

```python
def scramble(L):
  A = L
  i = 2
  while (i < len(A)):
    A[i-2] += A.pop(i-1)
    A[i-1].append(A[:i-2])
    i += 1
    
  return L

def get_flag():
  flag = open('flag.txt', 'r').read()
  flag = flag.strip()
  hex_flag = []
  for c in flag:
    hex_flag.append([str(hex(ord(c)))])

  return hex_flag

def main():
  flag = get_flag()
  cypher = scramble(flag)
  print(cypher)
```
Let's start with  `getFlag`, this function opens a file called flag.txt and then, character by character appends to a new list, the corresponding ASCII number expressed in hexadecimal.

Now, scramble, for convenience, I will rename the variables to something that has meaning, this is extremely useful in more complex cases.

``` python
def scramble(flagList):
  flagListCopy = flagList
  i = 2
  while (i < len(flagListCopy)):
    flagListCopy[i-2] += flagListCopy.pop(i-1)
    flagListCopy[i-1].append(flagListCopy[:i-2])
    i += 1
    
  return flagList
```
For this function, the first thing I noticed is that in the loop, we are modifying flagListCopy, but the return is flagList. However, Python performs a shallow copy, both lists are in the same memory address, so when we edit flagListCopy, we edit both.

Now, to understand what's happening in this loop, we can use pen and paper to do at least the first iteration. Doing this, you will notice that the second value is popped and then, gets appended to the first. After that, we access the second element in the list, and append all the elements from the position 0, to the position 0, being this, an empty list.

However, this approach gets harder with each iteration, so, to perform the analysis, I created a flag.txt with "helo1234" inside. And, some code to visualize better what the algorithm is doing by converting hex back into char.


``` python
def hex_to_char(L):
    if isinstance(L, list):
        return [hex_to_char(x) for x in L]
    elif isinstance(L, str):
        return chr(int(L, 16))
    else:
        return L

``` 
With this, we can test the code, and with some print statements we get:
``` 
FLAG
[['0x68'], ['0x65'], ['0x6c'], ['0x6c'], ['0x6f'], ['0x31'], ['0x32'], ['0x33'], ['0x34']]
['h', 'e', 'l', 'l', 'o', '1', '2', '3', '4']
Scrambled
[['0x68', '0x65'], ['0x6c', [], '0x6c'], ['0x6f', [['0x68', '0x65']], '0x31'], ['0x32', [['0x68', '0x65'], ['0x6c', [], '0x6c']], '0x33'], ['0x34', [['0x68', '0x65'], ['0x6c', [], '0x6c'], ['0x6f', [['0x68', '0x65']], '0x31']]]]
Scrambled to char
[['h', 'e'], ['l', [], 'l'], ['o', [['h', 'e']], '1'], ['2', [['h', 'e'], ['l', [], 'l']], '3'], ['4', [['h', 'e'], ['l', [], 'l'], ['o', [['h', 'e']], '1']]]]
``` 

Seeing this, you can notice how the first 2 elements of the list are what we expected (notice that the second "l" after the empty list got appended on the second iteration), and the other ones, don't make sense at all.
Now the Hint 2 comes in handy: `Print the outer list one object per line`
``` 
By line
['h', 'e']
['l', [], 'l']
['o', [['h', 'e']], '1']
['2', [['h', 'e'], ['l', [], 'l']], '3']
['4', [['h', 'e'], ['l', [], 'l'], ['o', [['h', 'e']], '1']]]
``` 
Now, we can see that the message is encoded in the first and last element of each list, we just need to put them together and we will get our flag back.
``` python
def unscramble(scrambled):

    result = []
    i=0

    while i < len(scrambled) -1:
        result += scrambled[i][0] 
        result += scrambled[i][-1]
        i = i + 1

    result += scrambled[i][0]
    return(result)
# this returns ['h', 'e', 'l', 'l', 'o', '1', '2', '3', '4'] 
``` 
We have concluded the analysis of the source code.

## Ncat command
When we put the command `nc verbal-sleep.picoctf.net 57273` into the terminal, we will get back some scrambled flag. We will feed this into `unscramble` with an additional for flattening the lists.

``` python
def flatten(lst):
    """Recursively flatten a list of characters."""
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(flatten(item))
        else:
            result.append(str(item))
    return result

res = (''.join(flatten(unscramble(hex_to_char(flag)))))
# res = picoCTF{python_is_weirdb57142ffpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_wpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hieipicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_rdpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_wpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hieb5picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_wpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hieipicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_r71picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_wpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hieipicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_rdpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hispicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_wpicoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hopicoCpiTFpico{ppicoCpiTyn_picoCpiTFpico{ppicoCpiTytpicoCpiTFpico{hieb4}

``` 
Now, we only need to find the valid flag in this text with a regex.
``` python
pattern = re.compile(r'picoCTF{')

match = pattern.search(res)

if match:
    print("Found pattern:", match.group())
    print("At position:", match.span())

#Found pattern: picoCTF{
#At position: (0, 8) 
``` 
So the flag is...
`picoCTF{python_is_weirdb57142ff}`