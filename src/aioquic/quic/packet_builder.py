from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..buffer import Buffer, size_uint_var
from ..tls import Epoch
from .crypto import CryptoPair
from .logger import QuicLoggerTrace
from .packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    NON_IN_FLIGHT_FRAME_TYPES,
    PACKET_NUMBER_MAX_SIZE,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_MASK,
    QuicFrameType,
    is_long_header,
)

import time
import math
from . import Measurement_Headers

PACKET_MAX_SIZE = 1280
PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2

from aioquic.quic.configuration import EFMVariants

QuicDeliveryHandler = Callable[..., None]

def round_half_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.floor(n*multiplier + 0.5) / multiplier

"""
In the following, there is the end-host logic for all EFM variants.
Note that only the loss measurement techniques (LBit|QBit|RBit|TBit) are currently up to date.
The delay measurement variants have **not been tested**.
"""

class QBitCounter:
    def __init__(self):

        self.current_square_output = False
        self.current_square_block_counter = 0
        return

    def get_qbit(self):
        """ Send out QBit """

        self.current_square_block_counter += 1

        ### Change the outgoing signal after 64 packets
        if self.current_square_block_counter > 64:
            self.current_square_output = not self.current_square_output
            self.current_square_block_counter = 1

        return self.current_square_output



class RBitCounter:
    def __init__(self):

        ## Current width of the reflection blocks
        self.current_reflection_block_width = 0

        ## Number of square bits received in the current period
        self.current_square_bits_receive_counter = 0

        """
        This is the reordering protection.
        We use a reordering threshold of 8 packets.
        """
        ## Number of square bits belonging to the next square period before reaching the treshold
        self.square_threshold_counter = 0
        self.square_threshold = 8

        ## Square bit value that is currently being received
        self.current_square_receive = False
        ## Current reflection bit value that is currently output
        self.current_reflection_output = False
        self.current_reflection_block_counter = 0

        ## Reflection mode is enabled after a first complete Q bit block
        self.reflection_active = False

        ## New blocks arriving during a reflection phase
        self.buffer_new_q_blocks_since_last_rbit_flip = []

        return


    def receive_qbit(self, received_square_bit):

        ### QBit has not changed
        if received_square_bit == self.current_square_receive:
            self.current_square_bits_receive_counter += 1

        ### Qbit has changed
        else:

            self.square_threshold_counter += 1

            """
            Q-Block has been completed and filtering treshold is passed.
            This is the reordering protection
            """
            if self.square_threshold_counter == self.square_threshold:

                ### Enable the reflection once in the beginning (that call is redundant for further iterations)
                self.reflection_active = True
                self.current_square_receive = received_square_bit
                
                """ Immediately update the R block length
                First, add the new qblock to the list of qblocks that have finished since the last rbit flip
                Then, compute the new average qblock length to adjust the current R block length
                """
                self.buffer_new_q_blocks_since_last_rbit_flip.append(self.current_square_bits_receive_counter)
                self.current_reflection_block_width = int(round_half_up(sum(self.buffer_new_q_blocks_since_last_rbit_flip)/len(self.buffer_new_q_blocks_since_last_rbit_flip)))

                self.current_square_bits_receive_counter = self.square_threshold
                self.square_threshold_counter = 0
                

    def get_rbit(self):
        """ Send out RBit """

        if self.reflection_active:
            self.current_reflection_block_counter += 1

            if self.current_reflection_block_counter > self.current_reflection_block_width:
                self.current_reflection_output = not self.current_reflection_output
                self.current_reflection_block_counter = 1

                ## if there were completely received Q blocks since the last R bit flip: clear them
                if len(self.buffer_new_q_blocks_since_last_rbit_flip) > 0:
                    self.buffer_new_q_blocks_since_last_rbit_flip = []

        return self.current_reflection_output


    
class LBitCounter:
    def __init__(self):
        self.value = 0
        return
    
    def increment(self):
        self.value += 1

    def get_lbit(self):
        """ Send out LBit """
        if self.value > 0:
            self.value -= 1
            return 1
        else:
            return 0



"""
TBit end-host logic for a QUIC client.
The client handles phase transitions and manages the whole TBit process.
"""
class TBitClient:

    def __init__(self):
        self.generation_token_counter = 0
        self.reflection_counter = 0

        self.phase = 1
        self.available_phases = {   1: "generation_probing", 
                                    2: "generation_generation",
                                    3: "pause_phase1",
                                    4: "reflection_generation",
                                    5: "reflection_counting",
                                    6: "pause_phase2"}

        self.loss_phase_without_t_bit = True

        return

    def get_tbit(self):
        """ Send out TBit """

        ### Generation
        if self.phase == 1:
            return False

        elif self.phase == 2:

            ### Send out as many packets with a set T bit as specified by the generation token counter
            if self.generation_token_counter > 0:
                self.generation_token_counter -= 1
                return True

        ## Pause
        elif self.phase == 3:
            return False

        ### Reflection
        elif self.phase == 4 or self.phase == 5:

            ### Send out as many packets with a set T bit as specified by the generation token counter and the reflection counter
            if self.reflection_counter > 0 and self.generation_token_counter > 0:
                self.reflection_counter -= 1
                self.generation_token_counter -= 1
                return True

        elif self.phase == 6:
            return False
    
        return False

    
    def incoming_packet(self):
        """
        Called on every incoming packet and handles the generation token counter.
        We currently cap the token counter at 1 so that we will only send a packet with a set TBit if we have received a packet since sending the previous packet with a set TBit. 
        """

        if self.generation_token_counter < 1:
            self.generation_token_counter += 1



    def receive_tbit(self, bit):
        if bit == False:
            return

        else:
            self.loss_phase_without_t_bit = False

            ### Implicitly enable relection_counter using dedicated phases
            if self.phase == 2 or self.phase == 3 or self.phase == 4:
                self.reflection_counter += 1



    def spin_flip(self):
        """
        Phase transitions are triggered by spin bit flips.
        """

        ## Pause phase transitions
        if self.phase == 3:
            
            ### There was an entire spin bit phase without any set TBit -> leave pause phase
            if self.loss_phase_without_t_bit:        
                self.phase = 4
            else:
                self.loss_phase_without_t_bit = True

        
        elif self.phase == 6:
            
            ### There was an entire spin bit phase without any set TBit -> leave pause phase
            if self.loss_phase_without_t_bit:
                self.phase = 1
                self.generation_token_counter = 0
            else:
                self.loss_phase_without_t_bit = True


        ## Generation Probing -> Generation Generation
        elif self.phase == 1:
            self.phase = 2
            ## Implictly enable reflection_counter by resetting it to 0 here and using a dedicated phase for counting
            self.reflection_counter = 0

        # Generation Generation -> Pause 1 
        elif self.phase == 2:
            self.phase = 3
            self.loss_phase_without_t_bit = True

        # Reflection Generation -> Reflection Counting
        elif self.phase == 4:
            ### Implicitly lock reflection_counter by having a dedicated phase that does not use it
            self.phase = 5

        ### Reflection Counting -> Pause 2
        elif self.phase == 5:
            self.phase = 6
            self.loss_phase_without_t_bit = True

"""
TBit end-host logic for a QUIC server.
The server only mirrors incoming TBits, nothing more to do
"""
class TBitServer:
    def __init__(self):
        self.counter = 0

    def receive_tbit(self, bit):
        if bit == True:
            self.counter += 1
        
    def get_tbit(self):
        if self.counter > 0:
            self.counter -= 1
            return True

        return False

    def incoming_packet(self):
        pass

    def enable_generation(self):
        pass



"""
This class contains an implementation of the VEC algorithm as specified in the IMC '18 paper of Piet de Vaere.
The implementation bases on the original implementation in https://github.com/mami-project/three-bits-suffice/
It has **not been tested**. 
"""
class ValidEdgeCounter:
    def __init__(self):
        
        self.latencyRxEdgeTime_ms = 0
        self.generateEdge = False
        self.latencyRxTxDelayMax_ms = 50
        self.vec_phase = 0


        self.noEdgeCounter = 0
        self.EdgeCounter = 0
    
    def setEdgeRXTime(self, time):
        self.latencyRxEdgeTime_ms = time * 1000

    def timelyEdge(self):
        return (time.time()*1000 - self.latencyRxEdgeTime_ms) < self.latencyRxTxDelayMax_ms

    def set_generateEdge(self):
        self.generateEdge = True

    def unset_generateEdge(self):
        self.generateEdge = False


    def get_vec_bits(self):

        if not self.generateEdge:
            self.noEdgeCounter += 1
            return (0,0)

        else:

            self.EdgeCounter += 1
            self.generateEdge = False
            if self.timelyEdge():
                
                self.vec_phase += 1
                if self.vec_phase > 3:
                    self.vec_phase = 3

            else:
                print("Edge too late")
                self.vec_phase = 0

            return (self.get_vec_high_bit(),self.get_vec_low_bit())

    def get_vec_high_bit(self):

        if self.vec_phase >= 2:
            return 1
        return 0

    def get_vec_low_bit(self):

        if self.vec_phase % 2 == 1:
            return 1
        return 0 

    def set_phase(self, high_bit, low_bit):

        self.vec_phase = high_bit * 2 + low_bit


"""
This class contains an implementation of the delay bit algorithm as specified in the ANRW '19 paper of Fabio Bulgarella.
It has **not been tested**.
"""
class DelayMarkerPaper:
    def __init__(self, is_client):
        self.generation_flag = 0
        self.previous_spin = 0
        self.dropped = False

        self.is_client = is_client
        
        # The client sets the delay bit of the first packet to 1
        self.mark_next = 1 if is_client else 0
        self.received_spin = 1

    
    def set_mark_next(self, received_spin):
        self.received_spin = received_spin
        self.mark_next = True


    """
    This function holds the logic of when to set the delay bit and is called when assembling a packet
    """
    def get_delay_bit(self, spin):
        """ Send out Delay Bit """

        if self.previous_spin != spin:
            if self.generation_flag == 1:
                self.generation_flag = 2
            
            if self.generation_flag == 2:
                self.generation_flag = 0
                self.dropped = False
                return 1

        self.previous_spin = spin

        if not self.mark_next:
            return 0

        self.mark_next = False

        if not self.is_client:
            # server marks it, if outgoing packet has the same spin value as the last received packet
            if spin == self.received_spin:
                return 1
            else:
                # print("server dropped delay bit")
                self.dropped = True
                return 0

        else: 
            # cient marks it, if outgoing packet has the opposite spin value
            if spin != self.received_spin:
                return 1
            else:
                # print("client dropped delay bit")
                self.dropped = True
                return 0

    def trigger_generation(self):
        if self.generation_flag == 0:
            # print("regeneration triggered")
            self.generation_flag = 1



"""
This class contains an implementation of an older variant of the delay bit algorithm as specified in the IPPM draft
It has **not been tested**.
Additionally, there is now a new variant in an updated version of the draft. 
"""
class DelayMarkerDraft:

    def __init__(self, is_client):
        self.generation_flag = 0
        self.dropped = False

        self.is_client = is_client
        
        # The client sets the delay bit of the first packet to 1
        self.mark_next = 1 if is_client else 0
        
        self.delay_sample_timestamp_s = time.time()
        self.t_max_static_ms = 1000 

    
    def set_mark_next(self):
        self.mark_next = True


    """
    This function holds the logic of when to set the delay bit and is called when assembling a packet
    """
    def get_delay_bit(self):

        if self.is_client:

            # Force a new delay bit if there was no delay bit for t_max_static_ms or if mark_next was set
            if (time.time() - self.delay_sample_timestamp_s) * 1000 > self.t_max_static_ms or self.mark_next:

                self.mark_next = False
                self.delay_sample_timestamp_s = time.time()
                return 1
            
        ## server only sends delay bit if mark_next was set
        elif not self.is_client:

            if self.mark_next:
                self.mark_next = False
                return 1


        # If none of the options fit, set delay bit to 0
        return 0


class QuicDeliveryState(Enum):
    ACKED = 0
    LOST = 1
    EXPIRED = 2


@dataclass
class QuicSentPacket:
    epoch: Epoch
    in_flight: bool
    is_ack_eliciting: bool
    is_crypto_packet: bool
    packet_number: int
    packet_type: int
    sent_time: Optional[float] = None
    sent_bytes: int = 0

    delivery_handlers: List[Tuple[QuicDeliveryHandler, Any]] = field(
        default_factory=list
    )
    quic_logger_frames: List[Dict] = field(default_factory=list)


class QuicPacketBuilderStop(Exception):
    pass


class QuicPacketBuilder:
    """
    Helper for building QUIC packets.
    """

    def __init__(
        self,
        *,
        host_cid: bytes,
        peer_cid: bytes,
        version: int,
        is_client: bool,
        packet_number: int = 0,
        peer_token: bytes = b"",
        quic_logger: Optional[QuicLoggerTrace] = None,
        spin_bit: bool = False,
        qbit: QBitCounter = None,
        valid_edge_counter: ValidEdgeCounter = None,
        rbit: RBitCounter = None,
        lbit: LBitCounter = None,
        delay_marker_paper: DelayMarkerPaper = None,
        delay_marker_draft: DelayMarkerDraft = None,
        tbit = None,
        efm_variants: EFMVariants = None,
    ):
        self.max_flight_bytes: Optional[int] = None
        self.max_total_bytes: Optional[int] = None
        self.quic_logger_frames: Optional[List[Dict]] = None

        self._host_cid = host_cid
        self._is_client = is_client
        self._peer_cid = peer_cid
        self._peer_token = peer_token
        self._quic_logger = quic_logger
        self._spin_bit = spin_bit
        self._version = version

        # assembled datagrams and packets
        self._datagrams: List[bytes] = []
        self._datagram_flight_bytes = 0
        self._datagram_init = True
        self._packets: List[QuicSentPacket] = []
        self._flight_bytes = 0
        self._total_bytes = 0

        # current packet
        self._header_size = 0
        self._packet: Optional[QuicSentPacket] = None
        self._packet_crypto: Optional[CryptoPair] = None
        self._packet_long_header = False
        self._packet_number = packet_number
        self._packet_start = 0
        self._packet_type = 0

        self._buffer = Buffer(PACKET_MAX_SIZE)
        self._buffer_capacity = PACKET_MAX_SIZE
        self._flight_capacity = PACKET_MAX_SIZE

        self.qbit = qbit
        self.valid_edge_counter = valid_edge_counter
        self.rbit = rbit
        self.lbit = lbit
        self.delay_marker_paper = delay_marker_paper
        self.delay_marker_draft = delay_marker_draft
        self.tbit = tbit
        self.efm_variants = EFMVariants(int(efm_variants))


    @property
    def packet_is_empty(self) -> bool:
        """
        Returns `True` if the current packet is empty.
        """
        assert self._packet is not None
        packet_size = self._buffer.tell() - self._packet_start
        return packet_size <= self._header_size

    @property
    def packet_number(self) -> int:
        """
        Returns the packet number for the next packet.
        """
        return self._packet_number

    @property
    def remaining_buffer_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._buffer_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

    @property
    def remaining_flight_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._flight_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

    def flush(self) -> Tuple[List[bytes], List[QuicSentPacket]]:
        """
        Returns the assembled datagrams.
        """
        if self._packet is not None:
            self._end_packet()
        self._flush_current_datagram()

        datagrams = self._datagrams
        packets = self._packets
        self._datagrams = []
        self._packets = []
        return datagrams, packets

    def start_frame(
        self,
        frame_type: int,
        capacity: int = 1,
        handler: Optional[QuicDeliveryHandler] = None,
        handler_args: Sequence[Any] = [],
    ) -> Buffer:
        """
        Starts a new frame.
        """
        if self.remaining_buffer_space < capacity or (
            frame_type not in NON_IN_FLIGHT_FRAME_TYPES
            and self.remaining_flight_space < capacity
        ):
            raise QuicPacketBuilderStop

        self._buffer.push_uint_var(frame_type)
        if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
            self._packet.is_ack_eliciting = True
        if frame_type not in NON_IN_FLIGHT_FRAME_TYPES:
            self._packet.in_flight = True
        if frame_type == QuicFrameType.CRYPTO:
            self._packet.is_crypto_packet = True
        if handler is not None:
            self._packet.delivery_handlers.append((handler, handler_args))
        return self._buffer

    def start_packet(self, packet_type: int, crypto: CryptoPair) -> None:
        """
        Starts a new packet.
        """
        buf = self._buffer

        # finish previous datagram
        if self._packet is not None:
            self._end_packet()

        # if there is too little space remaining, start a new datagram
        # FIXME: the limit is arbitrary!
        packet_start = buf.tell()
        if self._buffer_capacity - packet_start < 128:
            self._flush_current_datagram()
            packet_start = 0

        # initialize datagram if needed
        if self._datagram_init:
            if self.max_total_bytes is not None:
                remaining_total_bytes = self.max_total_bytes - self._total_bytes
                if remaining_total_bytes < self._buffer_capacity:
                    self._buffer_capacity = remaining_total_bytes

            self._flight_capacity = self._buffer_capacity
            if self.max_flight_bytes is not None:
                remaining_flight_bytes = self.max_flight_bytes - self._flight_bytes
                if remaining_flight_bytes < self._flight_capacity:
                    self._flight_capacity = remaining_flight_bytes
            self._datagram_flight_bytes = 0
            self._datagram_init = False

        # calculate header size
        packet_long_header = is_long_header(packet_type)
        if packet_long_header:
            header_size = 11 + len(self._peer_cid) + len(self._host_cid)
            if (packet_type & PACKET_TYPE_MASK) == PACKET_TYPE_INITIAL:
                token_length = len(self._peer_token)
                header_size += size_uint_var(token_length) + token_length
        else:

            ### Account for measurement header (which is 1 Byte longer)
            if Measurement_Headers.Active:
                header_size = 4 + len(self._peer_cid)
            else:
                header_size = 3 + len(self._peer_cid)

        # check we have enough space
        if packet_start + header_size >= self._buffer_capacity:
            raise QuicPacketBuilderStop

        # determine ack epoch
        if packet_type == PACKET_TYPE_INITIAL:
            epoch = Epoch.INITIAL
        elif packet_type == PACKET_TYPE_HANDSHAKE:
            epoch = Epoch.HANDSHAKE
        else:
            epoch = Epoch.ONE_RTT

        self._header_size = header_size
        self._packet = QuicSentPacket(
            epoch=epoch,
            in_flight=False,
            is_ack_eliciting=False,
            is_crypto_packet=False,
            packet_number=self._packet_number,
            packet_type=packet_type,
        )
        self._packet_crypto = crypto
        self._packet_long_header = packet_long_header
        self._packet_start = packet_start
        self._packet_type = packet_type
        self.quic_logger_frames = self._packet.quic_logger_frames

        buf.seek(self._packet_start + self._header_size)

    def _end_packet(self) -> None:
        """
        Ends the current packet.
        """
        buf = self._buffer
        packet_size = buf.tell() - self._packet_start
        if packet_size > self._header_size:
            # padding to ensure sufficient sample size
            padding_size = (
                PACKET_NUMBER_MAX_SIZE
                - PACKET_NUMBER_SEND_SIZE
                + self._header_size
                - packet_size
            )

            # padding for initial datagram
            if (
                self._is_client
                and self._packet_type == PACKET_TYPE_INITIAL
                and self._packet.is_ack_eliciting
                and self.remaining_flight_space
                and self.remaining_flight_space > padding_size
            ):
                padding_size = self.remaining_flight_space

            # write padding
            if padding_size > 0:
                buf.push_bytes(bytes(padding_size))
                packet_size += padding_size
                self._packet.in_flight = True

                # log frame
                if self._quic_logger is not None:
                    self._packet.quic_logger_frames.append(
                        self._quic_logger.encode_padding_frame()
                    )

            # write header
            if self._packet_long_header:
                length = (
                    packet_size
                    - self._header_size
                    + PACKET_NUMBER_SEND_SIZE
                    + self._packet_crypto.aead_tag_size
                )

                buf.seek(self._packet_start)
                buf.push_uint8(self._packet_type | (PACKET_NUMBER_SEND_SIZE - 1))
                buf.push_uint32(self._version)
                buf.push_uint8(len(self._peer_cid))
                buf.push_bytes(self._peer_cid)
                buf.push_uint8(len(self._host_cid))
                buf.push_bytes(self._host_cid)
                if (self._packet_type & PACKET_TYPE_MASK) == PACKET_TYPE_INITIAL:
                    buf.push_uint_var(len(self._peer_token))
                    buf.push_bytes(self._peer_token)
                buf.push_uint16(length | 0x4000)
                buf.push_uint16(self._packet_number & 0xFFFF)
            else:
                buf.seek(self._packet_start)


                """
                Construct the packets depending on whether we use the measurementheader or not.
                Note: This variant also includes several delay measurement variants. These have **not been tested**.
                """


                if Measurement_Headers.Active:
                    vec_high, vec_low = self.valid_edge_counter.get_vec_bits()
                    data = self._packet_type | (self._spin_bit << 5) | (vec_high << 4) | (vec_low << 3) | (self.delay_marker_paper.get_delay_bit(self._spin_bit) << 2) | (self.delay_marker_draft.get_delay_bit() << 1) | 0

                    buf.push_uint8(
                        data
                    )

                    data_2 = (self.qbit.get_qbit() << 7) | (self.rbit.get_rbit() << 6) |  (self.lbit.get_lbit() << 5) | (self.tbit.get_tbit() << 4) | 0 << 3 | (self._packet_crypto.key_phase << 2) | (PACKET_NUMBER_SEND_SIZE - 1)

                    buf.push_uint8(
                        data_2
                    )

                else:

                    data = self._packet_type | (self._spin_bit << 5) | (self._packet_crypto.key_phase << 2) | (PACKET_NUMBER_SEND_SIZE - 1)


                    """
                    Depending on the chosen measurement configuration, scramble different EFM bits into the reserved bits
                    """
                    if self.efm_variants == EFMVariants.SPIN_DELAY_PAPER_T_BIT_RTPL:
                        data = data  | (self.delay_marker_paper.get_delay_bit(self._spin_bit) << 4) | (self.tbit.get_tbit() << 3)

                    if self.efm_variants == EFMVariants.SPIN_Q_BIT_SQUARE_R_BIT_REFLECTION_SQUARE:
                        data = data | (self.qbit.get_qbit() << 4) | (self.rbit.get_rbit() << 3)

                    if self.efm_variants == EFMVariants.SPIN_Q_BIT_SQUARE_L_BIT_LOSS_EVENT:
                        data = data | (self.qbit.get_qbit() << 4) | (self.lbit.get_lbit() << 3)

                    if self.efm_variants == EFMVariants.SPIN_VEC:

                        vec_high, vec_low = self.valid_edge_counter.get_vec_bits()
                        data = data | (vec_high << 4) | (vec_low << 3)

                    
                    if self.efm_variants == EFMVariants.SPIN_DELAY_DRAFT_T_BIT_RTPL:
                        data = data  | (self.delay_marker_draft.get_delay_bit() << 4) | (self.tbit.get_tbit() << 3)

                    buf.push_uint8(
                        data
                    )

                buf.push_bytes(self._peer_cid)
                buf.push_uint16(self._packet_number & 0xFFFF)

            # encrypt in place
            plain = buf.data_slice(self._packet_start, self._packet_start + packet_size)
            buf.seek(self._packet_start)
            buf.push_bytes(
                self._packet_crypto.encrypt_packet(
                    plain[0 : self._header_size],
                    plain[self._header_size : packet_size],
                    self._packet_number,
                )
            )
            self._packet.sent_bytes = buf.tell() - self._packet_start
            self._packets.append(self._packet)
            if self._packet.in_flight:
                self._datagram_flight_bytes += self._packet.sent_bytes

            # short header packets cannot be coallesced, we need a new datagram
            if not self._packet_long_header:
                self._flush_current_datagram()

            self._packet_number += 1
        else:
            # "cancel" the packet
            buf.seek(self._packet_start)

        self._packet = None
        self.quic_logger_frames = None

    def _flush_current_datagram(self) -> None:
        datagram_bytes = self._buffer.tell()
        if datagram_bytes:
            self._datagrams.append(self._buffer.data)
            self._flight_bytes += self._datagram_flight_bytes
            self._total_bytes += datagram_bytes
            self._datagram_init = True
            self._buffer.seek(0)

