local XorDecrypt = {}

--Returns the XOR of two binary numbers
function xor(a,b)
  local r = 0
  local f = math.floor
  for i = 0, 31 do
    local x = a / 2 + b / 2
    if x ~= f(x) then
      r = r + 2^i
    end
    a = f(a / 2)
    b = f(b / 2)
  end
  return r
end
 
--Changes a HEX to a binary number
function toBits(num)
    local t={}
    while num>0 do
        rest=math.fmod(num,2)
        t[#t+1]=rest
        num=(num-rest)/2
    end
	--[[ t gives the binary number in reverse. To fix this
		the bits table will give the correct value
		by reversing the values in t.
		The result will be left paddied with zeros to eight digits
	]]
	local bits = {}
	local lpad = 8 - #t
	if lpad > 0 then
		for c = 1,lpad do table.insert(bits,0) end
	end
	-- Reverse the values in t
	for i = #t,1,-1 do table.insert(bits,t[i]) end
 
    return table.concat(bits)
end
 
--Changes eight digit binary to decimal
function toDec(bits)
	local bmap = {128,64,32,16,8,4,2,1} --binary map
 
	local bitt = {}
	for c in bits:gmatch(".") do table.insert(bitt,c) end
 
	local result = 0
 
	for i = 1,#bitt do
		if bitt[i] == "1" then result = result + bmap[i] end
	end
 
	return result
end
 
--Encryption and Decryption Algorithm for XOR Block cipher
function XorDecrypt.E(text, key)
	
	-- Split the string into a table of binary number
	HexText = {}
	inc = 1
	
	for i = 1, #text,2 do
		HexText[inc] = toBits(tonumber(string.sub(text, i, i+1), 16))
		inc = inc+1
	end
	--split the key into an table of binary number
	HexKey = {}
	inc = 1
	
	for i = 1, #key, 2 do
		HexKey[inc] = toBits(tonumber(string.sub(key, i, i+1), 16))
		inc = inc+1
	end
	-- for each binary number perform xor transformation with the corresponding key index binary number
	local block = {}
	j=0
	for k = 1,#HexText do
		local bitt = {}
		local bits = HexText[k]
		for c in bits:gmatch(".") do table.insert(bitt,c) end
		
		if (j>=#HexKey)then
			j=1
		else
			j=j+1
		end
		
		--split key[j] byte string into a table

		local ciphert = {}
		for c in HexKey[j]:gmatch(".") do 
			table.insert(ciphert,c) 
		end
		
		local result = {}
		for i = 1,8,1 do
			table.insert(result,xor(ciphert[i],bitt[i]))
		end
		block[k] = string.char(toDec(table.concat(result)))		
	end
		
		
		
	return table.concat(block)
	
end

return XorDecrypt

-------------------------------
-------------test case---------
-------------------------------

--mykey = "dafa47b7afa37df5" -- must be eight digit binary number
--Test Section
--print(XorDecrypt.E("9EBB13F684A37DF5D2FD1AF58E3D8E38CBFD1AF5FE54E04EBE8F1AF3893D8E39DBFD1A44943D8E39DBFD1A9EBB13F69AA37DF5D2FD1AF58C3D8E38C7FD1AF5E053E857DB942EA09DE3BAB1D9FF1AF5895FBF0FDBFD1AF5893D8E38DBFD1AF5899FB40399A7A37DF5", mykey))
--print(E("çÊÃÃÀøÀÝÃË")) -- returns 'Hello World'
--print(E("The quick brown fox jumps over the lazy moon"))
--print(E("ûÇÊÞÚÆÌÄÍÝÀØÁÉÀ×ÅÚÂßÜÀÙÊÝÛÇÊÃÎÕÖÂÀÀÁ")) -- returns 'The quick brown fox jumps over the lazy moon'