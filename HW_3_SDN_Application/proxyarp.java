package net.floodlightcontroller.ProxyARP;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.VlanVid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.*;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;

import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.topology.ITopologyService;


public class proxyarp extends TimerTask implements IOFMessageListener, IFloodlightModule {
	protected static final long BROADCAST_MAC = 0xffffffffffffL;
	protected static final long ARP_TIMEOUT = 5000L;
	protected static Logger logger;
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService SwitchServiceProvider;
	protected IDeviceService deviceManager;
	protected ITopologyService topologyManager;
	protected Map<Long, Set<ARPRequest>> arpRequests;
	protected Timer timer;
	
	
	/*Building ARPRequest object
	 */
	protected class ARPRequest {
		 
		private long sourceMACAddress;
		private long sourceIPAddress;
		private long targetMACAddress;
		private long targetIPAddress;
		private DatapathId switchId;
		private OFPort inPort;
		private long startTime;
		public ARPRequest setStartTime(long startTime) {
			this.startTime = startTime;
			return this;
		}
	}

	@Override
	public String getName() {
		return "ARPhandler";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		//l.add(IOFSwitchService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		topologyManager = context.getServiceImpl(ITopologyService.class);
		deviceManager = context.getServiceImpl(IDeviceService.class);
		logger = LoggerFactory.getLogger(proxyarp.class);	
		SwitchServiceProvider=context.getServiceImpl(IOFSwitchService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("ARPProxy-Modul started");
		}
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		arpRequests = new Hashtable<Long, Set<ARPRequest>>();
		timer = new Timer();
		timer.schedule(this, ARP_TIMEOUT, ARP_TIMEOUT);
	}

	@Override
	public Command receive(	IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
        	case PACKET_IN:
        		IRoutingDecision decision = null;
                if (cntx != null) {
                    decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
                }
                return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
        	default:
        		break;
			}
		return Command.CONTINUE;
	}
	

	protected Command processPacketInMessage(IOFSwitch sw, OFPacketIn piMsg, IRoutingDecision decision, FloodlightContext cntx) {
		/* Get the Ethernet frame representation of the PacketIn message. */
		Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// If this is not an ARP message, continue.
		System.out.println("in the process packet of proxyARP");
		if (ethPacket.getEtherType() != EthType.ARP )
			return Command.CONTINUE;
		
		/* A new empty ARP packet. */
		ARP arp = new ARP();
		
		// Get the ARP packet or continue.
		if (ethPacket.getPayload() instanceof ARP) {
            arp = (ARP) ethPacket.getPayload();
		} else {
			return Command.CONTINUE;
		}
		
		// If a decision has been made already we obey it.
		if (decision != null) {
			if (logger.isTraceEnabled()) {
                logger.trace("Forwaring decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), piMsg);
            }
			
			switch(decision.getRoutingAction()) {
            	case NONE:
            		return Command.CONTINUE;
            	case DROP:
            		return Command.CONTINUE;
            	case FORWARD_OR_FLOOD:
            		break;
            	case FORWARD:
            		break;
            	case MULTICAST:
            		break;
            	default:
            		logger.error("Unexpected decision made for this packet-in={}", piMsg, decision.getRoutingAction());
            		return Command.CONTINUE;
			}
		}
		
		// Handle ARP request.
		if (arp.getOpCode() == ARP.OP_REQUEST) {
			return this.handleARPRequest(arp, sw.getId(), piMsg.getMatch().get(MatchField.IN_PORT), cntx);
		}
		
		// Handle ARP reply.
		if (arp.getOpCode() == ARP.OP_REPLY) {
			return this.handleARPReply(arp, sw.getId(), piMsg.getMatch().get(MatchField.IN_PORT), cntx);
		}
		
		decision = new RoutingDecision(sw.getId(), piMsg.getInPort(), IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.NONE);
        decision.addToContext(cntx);
		
		return Command.CONTINUE;
	}
	
	/* This function
	 * Handles incoming ARP requests. Reads the relevant information, creates an ARPRequest
	 * object, sends out the ARP request message or, if the information is already known by
	 * the system, sends back an ARP reply message.
	
	 */
	protected Command handleARPRequest(ARP arp, DatapathId switchId, OFPort portId, FloodlightContext cntx) {
		System.out.println("***********************handling ARP request*****************************");
		long sourceIPAddress = IPv4.toIPv4Address(arp.getSenderProtocolAddress().toString());
		long sourceMACAddress = Ethernet.toLong(arp.getSenderHardwareAddress().getBytes());
		long targetIPAddress = IPv4.toIPv4Address(arp.getTargetProtocolAddress().toString());
		long targetMACAddress = 0;
		
		if (logger.isDebugEnabled()) {
			logger.debug("Received ARP request message from " + sourceMACAddress + " at " + switchId.toString() + " - " + portId + " for target: " + IPv4.fromIPv4Address(IPv4.toIPv4Address(arp.getTargetProtocolAddress().toString())));
		}
		
		// Check if there is an ongoing ARP process for this packet.
		if (arpRequests.containsKey(targetIPAddress)) {
			// Update start time of current ARPRequest objects
			long startTime = System.currentTimeMillis();
			Set<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				iter.next().setStartTime(startTime);
			}
			return Command.STOP;
		}
		
		
		@SuppressWarnings("unchecked")
		Iterator<Device> diter = (Iterator<Device>) deviceManager.queryDevices(MacAddress.NONE, VlanVid.ZERO, arp.getTargetProtocolAddress(),IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);	

		// There should be only one MAC address to the given IP address. In any case, 
		// we return only the first MAC address found.
	
		if (diter.hasNext()) {
			// If we know the destination device, get the corresponding MAC address and send an ARP reply.
			Device device = diter.next();
			targetMACAddress = Ethernet.toLong(device.getMACAddress().getBytes());
		
			if (targetMACAddress > 0) {
				ARPRequest arpRequest = new ARPRequest();
				arpRequest.sourceMACAddress=sourceMACAddress;
				arpRequest.sourceIPAddress=sourceIPAddress;
				arpRequest.targetMACAddress=targetMACAddress;
				arpRequest.targetIPAddress=targetIPAddress;
				arpRequest.switchId=switchId;
				arpRequest.inPort=portId;
				this.sendARPReply(arpRequest);
			} else {
				ARPRequest arpRequest = new ARPRequest();
				arpRequest.sourceMACAddress=sourceMACAddress;
				arpRequest.sourceIPAddress=sourceIPAddress;
				arpRequest.targetIPAddress=targetIPAddress;
				arpRequest.switchId=switchId;
				arpRequest.inPort=portId;
				arpRequest.startTime=System.currentTimeMillis();
				// Put new ARPRequest object to current ARPRequests list.
				this.putArpRequest(targetIPAddress, arpRequest);
				// Send ARP request.
				this.sendARPReqest(arpRequest);
			}
			
		} else {
			ARPRequest arpRequest = new ARPRequest();
			arpRequest.sourceMACAddress=sourceMACAddress;
			arpRequest.sourceIPAddress=sourceIPAddress;
			arpRequest.targetIPAddress=targetIPAddress;
			arpRequest.switchId=switchId;
			arpRequest.inPort=portId;
			arpRequest.startTime=System.currentTimeMillis();
			// Put new ARPRequest object to current ARPRequests list.		
			this.putArpRequest(targetIPAddress, arpRequest);
			// Send ARP request
			this.sendARPReqest(arpRequest);
		}
		
		// Make a routing decision and forward the ARP message
		IRoutingDecision decision = new RoutingDecision(switchId, portId, IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.NONE);
		decision.addToContext(cntx);
		
		return Command.CONTINUE;
	}
	
	/*This function
	 * Handles incoming ARP replies. 
	 */
	protected Command handleARPReply(ARP arp, DatapathId switchId, OFPort portId, FloodlightContext cntx) {
		
		System.out.println("*************handling ARP reply***********************");
		long targetIPAddress = IPv4.toIPv4Address(arp.getSenderProtocolAddress().toString());
		long sourceMACAddress = Ethernet.toLong(arp.getSenderHardwareAddress().getBytes());
		Set<ARPRequest> arpRequestSet = arpRequests.remove(targetIPAddress);
		ARPRequest arpRequest;
		
		if (logger.isDebugEnabled()) {
			logger.debug("Received ARP reply message from " + sourceMACAddress + " at " + switchId.toString() + " - " + portId.toString());
		}
		
		// If the ARP request has already timed out, consume the message.
		// The sending host should send a new request, actually.
		if (arpRequestSet == null)
			return Command.STOP;
		
		for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
			arpRequest = iter.next();
			iter.remove();
			arpRequest.targetMACAddress=Ethernet.toLong(arp.getSenderHardwareAddress().getBytes());
			sendARPReply(arpRequest);
		}
		
		// Making a routing decision and forward the ARP message..
		IRoutingDecision decision = new RoutingDecision(switchId, portId, IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.NONE);
		decision.addToContext(cntx);
						
		return Command.CONTINUE;
	}
	
	/*
	 * Creates an ARP request frame, puts it into a packet out message and 
	 * sends the packet out message to all switch ports (attachment point ports)
	 * that are not connected to other OpenFlow switches.
	 */
	protected void sendARPReqest(ARPRequest arpRequest) {
		// Create an ARP request frame
		IPacket arpReply = new Ethernet()
    		.setSourceMACAddress(Ethernet.toByteArray(arpRequest.sourceMACAddress))
        	.setDestinationMACAddress(Ethernet.toByteArray(BROADCAST_MAC))
        	.setEtherType(EthType.ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REQUEST)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(MacAddress.of(arpRequest.sourceMACAddress))
				.setSenderProtocolAddress(IPv4Address.of((int)arpRequest.sourceIPAddress))
				.setTargetHardwareAddress(MacAddress.of(arpRequest.targetMACAddress))
				.setTargetProtocolAddress(IPv4Address.of((int)arpRequest.targetIPAddress))
				.setPayload(new Data(new byte[] {0x01})));
		
		// Send ARP request to all external ports .
		for (DatapathId switchId : SwitchServiceProvider.getAllSwitchDpids()) {
			IOFSwitch sw = SwitchServiceProvider.getSwitch(switchId);
			for (OFPortDesc port : sw.getPorts()) {
				OFPort portId = port.getPortNo();
				if (switchId == arpRequest.switchId && portId == arpRequest.inPort) {
					continue;
				}
				if (topologyManager.isAttachmentPointPort(switchId, portId))
					this.sendPO(arpReply, sw, portId);
					if (logger.isDebugEnabled()) {
						logger.debug("Send ARP request to " + switchId.toString() + " at port " + portId.toString());
						
					}
					System.out.println("Send ARP request to " + switchId.toString() + " at port " + portId.toString());
			}
		}
	}
	
	/*This function Creates an ARP reply frame, puts it into a packet out message and 
	 * sends the packet out message to the switch that received the ARP
	 * request message.
	 */
	protected void sendARPReply(ARPRequest arpRequest) {
		// Create an ARP reply frame (from target (source) to source (destination)).
		IPacket arpReply = new Ethernet()
    		.setSourceMACAddress(Ethernet.toByteArray(arpRequest.targetMACAddress))
        	.setDestinationMACAddress(Ethernet.toByteArray(arpRequest.sourceMACAddress))
        	.setEtherType(EthType.ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REPLY)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(MacAddress.of(arpRequest.targetMACAddress))
				.setSenderProtocolAddress(IPv4Address.of((int)arpRequest.targetIPAddress))
				.setTargetHardwareAddress(MacAddress.of(arpRequest.sourceMACAddress))
				.setTargetProtocolAddress(IPv4Address.of((int)arpRequest.sourceIPAddress))
				.setPayload(new Data(new byte[] {0x01})));
		// Send ARP reply.
		sendPO(arpReply, SwitchServiceProvider.getSwitch(arpRequest.switchId), arpRequest.inPort);
		if (logger.isDebugEnabled()) {
			logger.debug("Send ARP reply to " + arpRequest.switchId.toString() + " at port " + arpRequest.inPort);
			
		}
		System.out.println("Send ARP reply to " + arpRequest.switchId.toString() + " at port " + arpRequest.inPort);
	}
	
	/*This function creates and sends an OpenFlow PacketOut message at a given port 
	 */
	protected void sendPO(IPacket packet, IOFSwitch sw, OFPort port) {		
		// Serialize and wrap in a packet out
		System.out.println("******************Packet Out message to switch*******************");
        byte[] data = packet.serialize();
        OFPacketOut.Builder po = sw.getOFFactory().buildPacketOut();
        po.setBufferId(OFBufferId.NO_BUFFER);
        po.setInPort(OFPort.ZERO);

        // Set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(sw.getOFFactory().actions().buildOutput().setPort(port).setMaxLen(0xffFFffFF).build());
        po.setActions(actions);
        po.setData(data);        
        sw.write(po.build());
       
       
	}
	
	/*
	 * Puts the current ARP request to a list of concurrent ARP requests.
	
	 */
	private void putArpRequest(long targetIPAddress, ARPRequest arpRequest) {
		if (arpRequests.containsKey(targetIPAddress)) {
			arpRequests.get(targetIPAddress).add(arpRequest);
		} else {
			arpRequests.put(targetIPAddress, new HashSet<ARPRequest>());
			arpRequests.get(targetIPAddress).add(arpRequest);
		}
	}
	
	/*This function
	 * Check for old ARP request. Remove ARP requests 
	 * older than ARP_TIMEOUT from the arpRequests data 
	 * structure.
	 */
	private void removeOldArpRequests() {
		/* The current time stamp. */
		long currentTime = System.currentTimeMillis();
		
		for (long targetIPAddress : arpRequests.keySet()) {
			Set<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				if ((currentTime - iter.next().startTime) > ARP_TIMEOUT)
					iter.remove();
				if (arpRequestSet.isEmpty()) 
					arpRequests.remove(targetIPAddress);
			}
		}
	}

	@Override
	public void run() {
		if (!arpRequests.isEmpty()) {
			this.removeOldArpRequests();
		}
	}

}
