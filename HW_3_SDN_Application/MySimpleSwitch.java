package net.floodlightcontroller.SimpleFirewall;


import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.util.LRULinkedHashMap;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.packet.ICMP;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.*;
import net.floodlightcontroller.packet.Ethernet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;

public class MySimpleFirewall  implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	static int count=0;
	static Map<String,Object> entry = new HashMap<String, Object>();
	static OFPort OutPort;
	static int a=0,b=0;//control variable
	
	// It is better to set up the learning switch reverse flow
	protected static final boolean LEARNING_SWITCH_REVERSE_FLOW = true;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return MySimpleFirewall.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		    l.add(ITopologyService.class);
		    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MySimpleFirewall.class);
	    
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		System.out.println("receive in myswitch");
		Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        OFPacketIn pi=(OFPacketIn)msg;
        Map<String, Object> getentry = new HashMap<String, Object>();
       
        	if(eth.getEtherType() == EthType.ARP) {
        	/* We got an ARP packet; get the payload from Ethernet */
            ARP arp = (ARP) eth.getPayload();
            System.out.println("*****Parsing ARP packet*******");
            /* Various getters and setters are exposed in ARP */
//          boolean gratuitous = arp.isGratuitous();
            logger.info("ARP ");
            //starting to write into the switch
            
            a=b;//control parameters to check if it finds the MAC:port information of the destination host
			
            getentry=addToPortMap(eth.getSourceMACAddress(),pi.getMatch().get(MatchField.IN_PORT));
            //DisplayMap(getentry);
           
            SearchPort(getentry,eth.getDestinationMACAddress());
            
            //if(OutPort!=null) //if it has found a port for the destination address
            if(a!=b)
            {   System.out.println("Unicasting the packet");
				//every flow constitutes of match and Actions...based on a particular match and an action is taken..both are used to modify a flow 
            	Match.Builder mb = sw.getOFFactory().buildMatch();
				//Source and destination MAC address along with the source port is set in the match
            	mb.setExact(MatchField.IN_PORT, pi.getMatch().get(MatchField.IN_PORT))
            	.setExact(MatchField.ETH_SRC, eth.getSourceMACAddress())
            	.setExact(MatchField.ETH_DST, eth.getDestinationMACAddress());
            	
				//build a packet to send to the switch in mininet
            	OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().buildOutput().setPort(OutPort).setMaxLen(0xffFFffFF).build());
                pob.setActions(actions);
                if (sw.getBuffers() == 0) {
    			// We set the PI buffer id here so we don't have to check again below
    			 pi = pi.createBuilder().setBufferId(OFBufferId.NO_BUFFER).build();
    			 pob.setBufferId(OFBufferId.NO_BUFFER);
    		    } else {
    			 pob.setBufferId(pi.getBufferId());
    		           }

    		    pob.setInPort(pi.getMatch().get(MatchField.IN_PORT));

				// If the buffer id is none or the switch doesn's support buffering
				// we send the data with the packet out...this is conditional
    		    if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
    			   byte[] packetData = pi.getData();
    			   pob.setData(packetData);
    			   System.out.println("writing into the packet");
    		       }
    		       //sw.write(pob.build()); //the reason to comment out the packet write to the switch is...we can either write a packet_out to the switch or
				   //we can just send a flow mod command to switch not both....
    		
    		//As we have written the payload to the switch, now we will write the
    		//flowmod command to the switch
    		//Create a Flow Mod Builder
    		    
    		    
    		this.writeFlowMod(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mb.build(), OutPort);
    		if (LEARNING_SWITCH_REVERSE_FLOW) {
    				Match.Builder mb_rev = sw.getOFFactory().buildMatch();
    				mb_rev.setExact(MatchField.ETH_SRC, mb.get(MatchField.ETH_DST))                         
    				.setExact(MatchField.ETH_DST, mb.get(MatchField.ETH_SRC))     
    				.setExact(MatchField.IN_PORT, OutPort);
    				

    			this.writeFlowMod(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mb_rev.build(), pi.getMatch().get(MatchField.IN_PORT));
    			}
    		    
            }
            else{
            	//System.out.println("Flooding the packet");
            	OFPort port = OFPort.FLOOD;
            	OFPacketOut.Builder pkout = sw.getOFFactory().buildPacketOut();
    			pkout.setBufferId(pi.getBufferId());
    			pkout.setXid(pi.getXid());
    			List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().buildOutput().setPort(port).setMaxLen(0xffFFffFF).build());
                pkout.setActions(actions);
    			
    			if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
    				pkout.setData(pi.getData());
    			}

    			sw.write(pkout.build());   	
            }       
        }           
        return Command.CONTINUE;
	}
	//This function creates a pairing of MAC address and the port number of the Source host
	
	public Map<String, Object> addToPortMap(MacAddress mac, OFPort portVal) {
		
		//Map<String,Object> entry = new HashMap<String, Object>();
		/*if the MAC_IP pair doesn't exit add
		 * 
		 */
		String srcPair=mac.toString();
		if(!entry.containsKey(srcPair)){
			String key=mac.toString();
			entry.put(key,portVal);
			return entry;
		}
		else{
			System.out.println("Key already exist");
			return entry;
		}
	}
	//this function just display the table
	public void DisplayMap(Map<String,Object> display){
		Set set=display.entrySet();
		Iterator i=set.iterator();
		while(i.hasNext()){
			Map.Entry me = (Map.Entry)i.next();
			System.out.println(me.getKey()+"  "+me.getValue());
		}
	}
	//this function search for the port number a MAC address is paired with...
	public void SearchPort(Map<String,Object> display,MacAddress mac){
		Set set=display.entrySet();
		Iterator i=set.iterator();
		String DestPair = mac.toString();
		System.out.println("DestPair:"+DestPair);
		
		while(i.hasNext()){
			
			Map.Entry me = (Map.Entry)i.next();
			System.out.println("existingPair:"+me.getKey());
			
			if (DestPair.equals(me.getKey())){
				System.out.println("The port to send"+me.getValue());
				OutPort = (OFPort)me.getValue();
				System.out.println("Output port"+OutPort.toString());
				b++;
				System.out.println("b value:"+b);
			}
			else{
				System.out.println("No port found");
			}
		
		}
	}
	//This is the main program that write a FlowMod to the switch
	private void writeFlowMod(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId,
			Match match, OFPort outPort){
		System.out.println("Writing flow to the Switch");
		OFFlowMod.Builder fmb;
		if (command == OFFlowModCommand.DELETE) {
			fmb = sw.getOFFactory().buildFlowDelete();
		} else {
			fmb = sw.getOFFactory().buildFlowAdd();
		}
		fmb.setMatch(match);
		fmb.setCookie((U64.of(LearningSwitch.LEARNING_SWITCH_COOKIE)));
		fmb.setIdleTimeout(20);
		fmb.setHardTimeout(0);
		fmb.setPriority(100);
		fmb.setBufferId(bufferId);
		fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);
		//Creating the action
		List<OFAction> al = new ArrayList<OFAction>();
		al.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build());
		fmb.setActions(al);

		if (logger.isTraceEnabled()) {
			logger.trace("{} {} flow mod {}",
					new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });
		}

		//counterFlowMod.increment();

		// and write it out
		sw.write(fmb.build());
	}
	
	
	
}