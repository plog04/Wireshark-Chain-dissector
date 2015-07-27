do
		-- Initialisation d'un nouveau protocole
        local tcp_wrapper_simple_proto = Proto("simple_tcp_extra", "Simple Extra analysis of the tcp protocol");
		
		-- Declaration des champs qui seront consultés afin d'obtenir leur valeur (à partir de protocole existant)
		f_get_TCP_port = Field.new("tcp.dstport")
		
		-- Declaration des champs qui seront ajouter à l'arbre de dissection du nouveau protocole
		TCP_port_F = ProtoField.string("tcp_extra.dstPort","Destination port")
	
		-- Ajout des champs au protocole		
		tcp_wrapper_simple_proto.fields = {TCP_port_F}
        
		local original_tcp_dissector
		
		-- Fonction du nouveau protocole qui sera executé sur chaque paquets d'un pcap
		function tcp_wrapper_simple_proto.dissector(tvbuffer, pinfo, treeitem)
		
			original_tcp_dissector:call(tvbuffer, pinfo, treeitem)
			
			-- obtain the current values the protocol fields			
			local tcp_dst_port = f_get_TCP_port()
			
			
			if tcp_dst_port then
				-- Creation de l'arbre de dissection de notre protocole
				local subtree = treeitem:add(tcp_wrapper_simple_proto,"Simple TCP Extra Protocol Data")
				-- Creation de la branche contenant la valeur du champ "tcp.dstport"
				local dstPort = tostring(tcp_dst_port)
				subtree:add(TCP_port_F,dstPort)
			end
		
        end
		
		-- On recupere l'object contenant les tables de dissecteur
        local tcp_dissector_table = DissectorTable.get("tcp.port")
		
		-- Sauvegarde le dissecteur TCP original (wireshark) afn de pouvoir encore y acceder
        original_tcp_dissector = tcp_dissector_table:get_dissector(443) 		
		
		-- Et on le remplace par notre dissecteur dans la table de dissecteur
        tcp_dissector_table:add(443, tcp_wrapper_simple_proto)                

end