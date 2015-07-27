-- Notre script permettant de decrypter en RC4 une string a partir d'une clé 
decryptor = require "myDissector/RC4"
do
		-- Initialisation d'un nouveau protocole
        local http_wrapper_proto = Proto("http_extra_Asprox_detection", "Extra analysis of the HTTP protocol to detect Asprox");
		
		-- Declaration des champs qui seront ajouter à l'arbre de dissection du nouveau protocole
		local F_RC4_Key = ProtoField.string("http.RC4_key", "The RC4 key", ftypes.STRING)
		local F_Encrypt_Url = ProtoField.string("http.Encrypt_URL", "The encrypted URL", ftypes.STRING)
		local F_Decrypt_Url = ProtoField.string("http.Decrypt_URL", "The decrypted URL", ftypes.STRING)
        
		-- Ajout des champs au protocole
        http_wrapper_proto.fields = {F_RC4_Key, F_Encrypt_Url, F_Decrypt_Url }      
        
		-- Declaration des champs que nous avons besoin de lire du protocol HTTP
		local f_set_URLKey = Field.new("http.request.uri")

        local original_http_dissector
        
		function http_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
 
                original_http_dissector:call(tvbuffer, pinfo, treeitem)
                
				if f_set_URLKey then
					if (f_set_URLKey()) then 					
						
						field1_val = string.sub(f_set_URLKey()(),2,9)
						field2_val = string.sub(f_set_URLKey()(),10)
						field3_val = decryptor.RC4(field1_val,field2_val)
						
						if (string.match(field3_val,"http") or string.match(field3_val,"php") or string.match(field3_val,"index") or string.match(field3_val,"gate")) then
							local subtreeitem = treeitem:add(http_wrapper_proto, tvbuffer)
							subtreeitem:append_text(" : On a trouver un url encrypter!")
							pinfo.cols.info = " - Asprox malware detected!!!!"
							pinfo.cols.protocol = "Analysed"
							subtreeitem:add(F_RC4_Key, tvbuffer(), field1_val)
									   :set_text("RC4 key to decrypt URL: " .. field1_val)
									   
							subtreeitem:add(F_Encrypt_Url, tvbuffer(), field2_val)
									   :set_text("Encrypted URL: " .. field2_val)
							subtreeitem:add(F_Decrypt_Url, tvbuffer(), field3_val)
									   :set_text("Decrypted URL: " .. field3_val)
						else
							subtreeitem:set_text("Asprox Detection Result")
						end	
					end
				end
        end
        local tcp_dissector_table = DissectorTable.get("tcp.port")
        original_http_dissector = tcp_dissector_table:get_dissector(8080)

        tcp_dissector_table:add(8080, http_wrapper_proto)               

end