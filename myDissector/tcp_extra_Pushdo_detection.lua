-- Notre script permettant de decrypter en XOR un string a partir d'une clé 
xOr = require "myDissector/XorDecrypt"
do
		-- Initialisation d'un nouveau protocole
        local tcp_wrapper_proto = Proto("tcp_extra_Pushdo_detection", "Extra analysis of the tcp protocol");
		
		-- Declaration des champs qui seront consultés afin d'obtenir leur valeur (à partir de protocole existant)
		f_get_TCP_port = Field.new("tcp.dstport")
		
		-- Declaration des champs qui seront ajouter à l'arbre de dissection du nouveau protocole
		TCP_port_F = ProtoField.string("tcp_extra_Pushdo_detection.dstPort","Destination port")
		TCP_segment_data1_F = ProtoField.string("tcp_extra_Pushdo_detection.segData1","Header key")
		TCP_segment_data2_F = ProtoField.string("tcp_extra_Pushdo_detection.segData2","Data key")
		TCP_segment_data3_F = ProtoField.string("tcp_extra_Pushdo_detection.encryptedData","Encrypted data and header")
		TCP_segment_data4_F = ProtoField.string("tcp_extra_Pushdo_detection.DecryptedData","Decrypted Header")
		TCP_segment_data5_F = ProtoField.string("tcp_extra_Pushdo_detection.DecryptedData2","Decrypted Data")
		
		-- Ajout des champs au protocole	
		tcp_wrapper_proto.fields = {TCP_port_F, TCP_segment_data1_F, TCP_segment_data2_F, TCP_segment_data3_F, TCP_segment_data4_F, TCP_segment_data5_F }
        
		local original_tcp_dissector
		function tcp_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
			if tvbuffer:len() == 0 then return end
				
				-- Appel la fonction d'analyse si l'ensemble des segments TCP > 30 bytes
				if tvbuffer:len() > 60 then
					 dissect_message(tvbuffer, pinfo, treeitem)
				else
					-- Cet attribut permet de fixer le numero du byte de départ dans le message pour le prochain segment TCP
					pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
				end
			
        end
		
		-- Fonction du nouveau protocole qui sera executé sur chaque paquets d'un pcap
		function dissect_message(buffer, pinfo, tree)
	
			if buffer:len() == 0 then return end
			
			original_tcp_dissector:call(buffer, pinfo, tree)
			
			-- Lecture de la valeur du champ venant du protocole originale		
			local tcp_dst_port = f_get_TCP_port()

									
			if tcp_dst_port then	
				if (tostring(tcp_dst_port) == "443" and string.find(tostring(buffer),"02000000")) then
							
					startIndex, endIndex = string.find(tostring(buffer),"02000000")			
					local HeaderKey = string.sub(tostring(buffer), endIndex+1, endIndex+16)								
					local DataKey = string.sub(tostring(buffer), endIndex+17, endIndex+17+15)								
					local DataLimit = string.sub(tostring(buffer), endIndex+17+16, endIndex+17+15+8)	-- Limiter par un probleme avec le buffer
					local DataFull = string.sub(tostring(buffer), endIndex+17+16)			
					local HeaderDecrypt = xOr.E(DataLimit, HeaderKey)
					local DataDecrypt = xOr.E(DataLimit, DataKey)

					-- Si les donnée decrypté contienne un des mots clés, creer l'arbre de dissection
					if (string.match(HeaderDecrypt,"DATA") or string.match(DataDecrypt,"winver")) then
						-- Creation de l'arbre de dissection de notre protocole
						local subtree = tree:add(tcp_wrapper_proto,"tcp_extra_Pushdo_detection Protocol Data")
						local dstPort = tostring(tcp_dst_port)
						subtree:add(TCP_port_F,dstPort)
						subtree:add(TCP_segment_data1_F,HeaderKey)
						subtree:add(TCP_segment_data2_F,DataKey)
						subtree:add(TCP_segment_data3_F, DataFull)
						subtree:add(TCP_segment_data4_F,HeaderDecrypt)
						subtree:add(TCP_segment_data5_F,DataDecrypt)
						pinfo.cols.protocol = "Analysed"
						pinfo.cols['info'] = ' - Pushdo malware detected!!!!'
					end

				end
			end
		
		end
		
		-- On recupere l'objet contenant les tables de dissecteur
        local tcp_dissector_table = DissectorTable.get("tcp.port")
		
		-- Sauvegarde le dissecteur TCP original (wireshark) afn de pouvoir encore y acceder
        original_tcp_dissector = tcp_dissector_table:get_dissector(443) 		
		
		-- Et on le remplace par notre dissecteur dans la table de dissecteur
        tcp_dissector_table:add(443, tcp_wrapper_proto)   
   		
end

