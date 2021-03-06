package org.batfish.grammar.fortios;

import static org.batfish.grammar.fortios.FortiosLexer.UNQUOTED_WORD_CHARS;

import com.google.common.collect.Range;
import java.util.HashMap;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.ErrorNode;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.batfish.common.Warnings;
import org.batfish.common.Warnings.ParseWarning;
import org.batfish.datamodel.ConcreteInterfaceAddress;
import org.batfish.datamodel.IntegerSpace;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.Ip6;
import org.batfish.grammar.BatfishCombinedParser;
import org.batfish.grammar.BatfishListener;
import org.batfish.grammar.UnrecognizedLineToken;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_editContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_commentContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_icmpcodeContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_icmptypeContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_protocolContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_protocol_numberContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_sctp_portrangeContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_tcp_portrangeContext;
import org.batfish.grammar.fortios.FortiosParser.Cfsc_set_udp_portrangeContext;
import org.batfish.grammar.fortios.FortiosParser.Cs_replacemsgContext;
import org.batfish.grammar.fortios.FortiosParser.Csg_hostnameContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_editContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_aliasContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_descriptionContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_ipContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_mtuContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_mtu_overrideContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_statusContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_typeContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_vdomContext;
import org.batfish.grammar.fortios.FortiosParser.Csi_set_vrfContext;
import org.batfish.grammar.fortios.FortiosParser.Csr_set_bufferContext;
import org.batfish.grammar.fortios.FortiosParser.Csr_unset_bufferContext;
import org.batfish.grammar.fortios.FortiosParser.Device_hostnameContext;
import org.batfish.grammar.fortios.FortiosParser.Double_quoted_stringContext;
import org.batfish.grammar.fortios.FortiosParser.Enable_or_disableContext;
import org.batfish.grammar.fortios.FortiosParser.Interface_aliasContext;
import org.batfish.grammar.fortios.FortiosParser.Interface_nameContext;
import org.batfish.grammar.fortios.FortiosParser.Interface_typeContext;
import org.batfish.grammar.fortios.FortiosParser.Ip_addressContext;
import org.batfish.grammar.fortios.FortiosParser.Ip_address_with_mask_or_prefixContext;
import org.batfish.grammar.fortios.FortiosParser.Ip_protocol_numberContext;
import org.batfish.grammar.fortios.FortiosParser.Ipv6_addressContext;
import org.batfish.grammar.fortios.FortiosParser.MtuContext;
import org.batfish.grammar.fortios.FortiosParser.Port_rangeContext;
import org.batfish.grammar.fortios.FortiosParser.Replacemsg_major_typeContext;
import org.batfish.grammar.fortios.FortiosParser.Replacemsg_minor_typeContext;
import org.batfish.grammar.fortios.FortiosParser.Service_nameContext;
import org.batfish.grammar.fortios.FortiosParser.Service_port_rangeContext;
import org.batfish.grammar.fortios.FortiosParser.Service_port_rangesContext;
import org.batfish.grammar.fortios.FortiosParser.Service_protocolContext;
import org.batfish.grammar.fortios.FortiosParser.Single_quoted_stringContext;
import org.batfish.grammar.fortios.FortiosParser.StrContext;
import org.batfish.grammar.fortios.FortiosParser.Subnet_maskContext;
import org.batfish.grammar.fortios.FortiosParser.Uint16Context;
import org.batfish.grammar.fortios.FortiosParser.Uint8Context;
import org.batfish.grammar.fortios.FortiosParser.Up_or_downContext;
import org.batfish.grammar.fortios.FortiosParser.VrfContext;
import org.batfish.grammar.fortios.FortiosParser.WordContext;
import org.batfish.representation.fortios.FortiosConfiguration;
import org.batfish.representation.fortios.Interface;
import org.batfish.representation.fortios.Interface.Type;
import org.batfish.representation.fortios.Replacemsg;
import org.batfish.representation.fortios.Service;
import org.batfish.representation.fortios.Service.Protocol;

/**
 * Given a parse tree, builds a {@link FortiosConfiguration} that has been prepopulated with
 * metadata and defaults by {@link FortiosPreprocessor}.
 */
public final class FortiosConfigurationBuilder extends FortiosParserBaseListener
    implements BatfishListener {

  public FortiosConfigurationBuilder(
      String text,
      FortiosCombinedParser parser,
      Warnings warnings,
      FortiosConfiguration configuration) {
    _text = text;
    _parser = parser;
    _w = warnings;
    _c = configuration;
  }

  @Override
  public String getInputText() {
    return _text;
  }

  @Override
  public BatfishCombinedParser<?, ?> getParser() {
    return _parser;
  }

  @Override
  public Warnings getWarnings() {
    return _w;
  }

  @Override
  public void exitCsg_hostname(Csg_hostnameContext ctx) {
    toString(ctx, ctx.host).ifPresent(_c::setHostname);
  }

  @Override
  public void enterCs_replacemsg(Cs_replacemsgContext ctx) {
    String majorType = toString(ctx.major_type);
    Optional<String> maybeMinorType = toString(ctx, ctx.minor_type);
    if (!maybeMinorType.isPresent()) {
      _currentReplacemsg = new Replacemsg(); // dummy
      return;
    }
    _currentReplacemsg =
        _c.getReplacemsgs()
            .computeIfAbsent(majorType, n -> new HashMap<>())
            .computeIfAbsent(maybeMinorType.get(), n -> new Replacemsg());
  }

  @Override
  public void exitCs_replacemsg(Cs_replacemsgContext ctx) {
    _currentReplacemsg = null;
  }

  @Override
  public void exitCsr_set_buffer(Csr_set_bufferContext ctx) {
    _currentReplacemsg.setBuffer(toString(ctx.buffer));
  }

  @Override
  public void exitCsr_unset_buffer(Csr_unset_bufferContext ctx) {
    _currentReplacemsg.setBuffer(null);
  }

  @Override
  public void enterCsi_edit(Csi_editContext ctx) {
    Optional<String> name = toString(ctx, ctx.interface_name());
    if (!name.isPresent()) {
      _currentInterface = new Interface(ctx.interface_name().getText()); // dummy
      return;
    }
    _currentInterface = _c.getInterfaces().computeIfAbsent(name.get(), Interface::new);
  }

  @Override
  public void exitCsi_edit(Csi_editContext ctx) {
    _currentInterface = null;
  }

  @Override
  public void exitCsi_set_vdom(Csi_set_vdomContext ctx) {
    _currentInterface.setVdom(toString(ctx.vdom));
  }

  @Override
  public void exitCsi_set_ip(Csi_set_ipContext ctx) {
    _currentInterface.setIp(toConcreteInterfaceAddress(ctx.ip));
  }

  @Override
  public void exitCsi_set_type(Csi_set_typeContext ctx) {
    _currentInterface.setType(toInterfaceType(ctx.type));
  }

  @Override
  public void exitCsi_set_alias(Csi_set_aliasContext ctx) {
    toString(ctx, ctx.alias).ifPresent(s -> _currentInterface.setAlias(s));
  }

  @Override
  public void exitCsi_set_status(Csi_set_statusContext ctx) {
    _currentInterface.setStatus(toStatus(ctx.status));
  }

  @Override
  public void exitCsi_set_mtu_override(Csi_set_mtu_overrideContext ctx) {
    _currentInterface.setMtuOverride(toBoolean(ctx.value));
  }

  @Override
  public void exitCsi_set_description(Csi_set_descriptionContext ctx) {
    _currentInterface.setDescription(toString(ctx.description));
  }

  @Override
  public void exitCsi_set_mtu(Csi_set_mtuContext ctx) {
    toInteger(ctx, ctx.value).ifPresent(m -> _currentInterface.setMtu(m));
  }

  @Override
  public void exitCsi_set_vrf(Csi_set_vrfContext ctx) {
    toInteger(ctx, ctx.value).ifPresent(v -> _currentInterface.setVrf(v));
  }

  @Override
  public void enterCfsc_edit(Cfsc_editContext ctx) {
    Optional<String> name = toString(ctx, ctx.service_name());
    if (!name.isPresent()) {
      _currentService = new Service(ctx.service_name().getText()); // dummy
      return;
    }
    _currentService = _c.getServices().computeIfAbsent(name.get(), Service::new);
  }

  @Override
  public void exitCfsc_set_comment(Cfsc_set_commentContext ctx) {
    _currentService.setComment(toString(ctx.comment));
  }

  @Override
  public void exitCfsc_set_icmpcode(Cfsc_set_icmpcodeContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.ICMP
        && _currentService.getProtocolEffective() != Protocol.ICMP6) {
      warn(
          ctx,
          String.format(
              "Cannot set ICMP code for service %s when protocol is not set to ICMP or ICMP6.",
              _currentService.getName()));
      return;
    }
    _currentService.setIcmpCode(toInteger(ctx.code));
  }

  @Override
  public void exitCfsc_set_icmptype(Cfsc_set_icmptypeContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.ICMP
        && _currentService.getProtocolEffective() != Protocol.ICMP6) {
      warn(
          ctx,
          String.format(
              "Cannot set ICMP type for service %s when protocol is not set to ICMP or ICMP6.",
              _currentService.getName()));
      return;
    }
    _currentService.setIcmpType(toInteger(ctx.type));
  }

  @Override
  public void exitCfsc_set_protocol(Cfsc_set_protocolContext ctx) {
    _currentService.setProtocol(toProtocol(ctx.protocol));
  }

  @Override
  public void exitCfsc_set_protocol_number(Cfsc_set_protocol_numberContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.IP) {
      warn(
          ctx,
          String.format(
              "Cannot set IP protocol number for service %s when protocol is not set to IP.",
              _currentService.getName()));
      return;
    }
    toInteger(ctx, ctx.ip_protocol_number()).ifPresent(_currentService::setProtocolNumber);
  }

  @Override
  public void exitCfsc_set_sctp_portrange(Cfsc_set_sctp_portrangeContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.TCP_UDP_SCTP) {
      warn(
          ctx,
          String.format(
              "Cannot set SCTP port range for service %s when protocol is not set to TCP/UDP/SCTP.",
              _currentService.getName()));
      return;
    }
    _currentService.setSctpPortRangeDst(toDstIntegerSpace(ctx.service_port_ranges()));
    _currentService.setSctpPortRangeSrc(toSrcIntegerSpace(ctx.service_port_ranges()).orElse(null));
  }

  @Override
  public void exitCfsc_set_tcp_portrange(Cfsc_set_tcp_portrangeContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.TCP_UDP_SCTP) {
      warn(
          ctx,
          String.format(
              "Cannot set TCP port range for service %s when protocol is not set to TCP/UDP/SCTP.",
              _currentService.getName()));
      return;
    }
    _currentService.setTcpPortRangeDst(toDstIntegerSpace(ctx.service_port_ranges()));
    _currentService.setTcpPortRangeSrc(toSrcIntegerSpace(ctx.service_port_ranges()).orElse(null));
  }

  @Override
  public void exitCfsc_set_udp_portrange(Cfsc_set_udp_portrangeContext ctx) {
    if (_currentService.getProtocolEffective() != Protocol.TCP_UDP_SCTP) {
      warn(
          ctx,
          String.format(
              "Cannot set UDP port range for service %s when protocol is not set to TCP/UDP/SCTP.",
              _currentService.getName()));
      return;
    }
    _currentService.setUdpPortRangeDst(toDstIntegerSpace(ctx.service_port_ranges()));
    _currentService.setUdpPortRangeSrc(toSrcIntegerSpace(ctx.service_port_ranges()).orElse(null));
  }

  /**
   * Convert specified service_port_ranges context into an IntegerSpace representing the destination
   * ports specified by the context.
   */
  private @Nonnull IntegerSpace toDstIntegerSpace(Service_port_rangesContext ctx) {
    IntegerSpace.Builder spaces = IntegerSpace.builder();
    for (Service_port_rangeContext range : ctx.service_port_range()) {
      assert range.dst_ports != null;
      spaces.including(toIntegerSpace(range.dst_ports));
    }
    return spaces.build();
  }

  /**
   * Convert specified service_port_ranges context into an optional IntegerSpace representing the
   * source ports specified by the context. An IntegerSpace is only returned if a source port space
   * is specified.
   */
  private Optional<IntegerSpace> toSrcIntegerSpace(Service_port_rangesContext ctx) {
    IntegerSpace.Builder spaces = IntegerSpace.builder();
    boolean isSet = false;
    for (Service_port_rangeContext range : ctx.service_port_range()) {
      if (range.src_ports != null) {
        isSet = true;
        spaces.including(toIntegerSpace(range.src_ports));
      }
    }
    return isSet ? Optional.of(spaces.build()) : Optional.empty();
  }

  private IntegerSpace toIntegerSpace(Port_rangeContext ctx) {
    int low = toInteger(ctx.port_low);
    if (ctx.port_high != null) {
      int high = toInteger(ctx.port_high);
      return IntegerSpace.of(Range.closed(low, high));
    }
    return IntegerSpace.of(low);
  }

  private Service.Protocol toProtocol(Service_protocolContext ctx) {
    if (ctx.ICMP() != null) {
      return Protocol.ICMP;
    } else if (ctx.ICMP6() != null) {
      return Protocol.ICMP6;
    } else if (ctx.IP_UPPER() != null) {
      return Protocol.IP;
    } else {
      assert ctx.TCP_UDP_SCTP() != null;
      return Protocol.TCP_UDP_SCTP;
    }
  }

  private boolean toBoolean(Enable_or_disableContext ctx) {
    if (ctx.ENABLE() != null) {
      return true;
    }
    assert ctx.DISABLE() != null;
    return false;
  }

  private Interface.Status toStatus(Up_or_downContext ctx) {
    if (ctx.UP() != null) {
      return Interface.Status.UP;
    }
    assert ctx.DOWN() != null;
    return Interface.Status.DOWN;
  }

  private Interface.Type toInterfaceType(Interface_typeContext ctx) {
    if (ctx.AGGREGATE() != null) {
      return Type.AGGREGATE;
    } else if (ctx.EMAC_VLAN() != null) {
      return Type.EMAC_VLAN;
    } else if (ctx.LOOPBACK() != null) {
      return Type.LOOPBACK;
    } else if (ctx.PHYSICAL() != null) {
      return Type.PHYSICAL;
    } else if (ctx.REDUNDANT() != null) {
      return Type.REDUNDANT;
    } else if (ctx.TUNNEL() != null) {
      return Type.TUNNEL;
    } else if (ctx.VLAN() != null) {
      return Type.VLAN;
    } else {
      assert ctx.WL_MESH() != null;
      return Type.WL_MESH;
    }
  }

  private @Nonnull ConcreteInterfaceAddress toConcreteInterfaceAddress(
      Ip_address_with_mask_or_prefixContext ctx) {
    if (ctx.ip_prefix() != null) {
      return ConcreteInterfaceAddress.parse(ctx.ip_prefix().getText());
    } else {
      assert ctx.ip_address() != null && ctx.subnet_mask() != null;
      return ConcreteInterfaceAddress.create(toIp(ctx.ip_address()), toIp(ctx.subnet_mask()));
    }
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, Service_nameContext ctx) {
    return toString(messageCtx, ctx.str(), "service name", SERVICE_NAME_PATTERN);
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, Interface_nameContext ctx) {
    return toString(messageCtx, ctx.str(), "interface name", INTERFACE_NAME_PATTERN);
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, Interface_aliasContext ctx) {
    return toString(messageCtx, ctx.str(), "interface alias", INTERFACE_ALIAS_PATTERN);
  }

  private @Nonnull String toString(Replacemsg_major_typeContext ctx) {
    return ctx.getText();
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, Replacemsg_minor_typeContext ctx) {
    return toString(messageCtx, ctx.word(), "replacemsg minor type");
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, Device_hostnameContext ctx) {
    return toString(messageCtx, ctx.str(), "device hostname", DEVICE_HOSTNAME_PATTERN);
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, StrContext ctx, String type, Pattern pattern) {
    return toString(messageCtx, ctx, type, s -> pattern.matcher(s).matches());
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, StrContext ctx, String type, Predicate<String> predicate) {
    String text = toString(ctx);
    if (!predicate.test(text)) {
      warn(messageCtx, String.format("Illegal value for %s", type));
      return Optional.empty();
    }
    return Optional.of(text);
  }

  private @Nonnull Optional<String> toString(
      ParserRuleContext messageCtx, WordContext ctx, String type) {
    return toString(messageCtx, ctx.str(), type, WORD_PATTERN);
  }

  private static @Nonnull String toString(StrContext ctx) {
    /*
     * Extract the text from a str.
     *
     * A str is composed of a sequence of single-quoted strings, double-quoted strings,
     * and unquoted non-whitespace characters.
     * - single-quoted strings do not interpret any characters specially
     * - double-quoted strings recognize the following three escape sequences:
     *   \" -> "
     *   \' -> ' <---Note that single-quotes are canonically escaped in double-quotes, but need not be.
     *   \\ -> \
     *   A backslash followed by any other character is treated as a literal backslash.
     *   So e.g.
     *   \n -> \n <---The letter 'n', not newline.
     * - outside of quotes, a backslash followed by any character other than a newline is stripped.
     *   E.g.
     *   \n -> n
     *   \" -> "
     *   \(space) -> (space)
     *   A backslash followed immediately by a newline character indicates a line continuation.
     *   That is, the backslash and the newline are both stripped.
     */
    return ctx.children.stream()
        .map(
            child -> {
              if (child instanceof Double_quoted_stringContext) {
                return toString((Double_quoted_stringContext) child);
              } else if (child instanceof Single_quoted_stringContext) {
                return toString((Single_quoted_stringContext) child);
              } else {
                assert child instanceof TerminalNode;
                int type = ((TerminalNode) child).getSymbol().getType();
                assert type == UNQUOTED_WORD_CHARS;
                return ESCAPED_UNQUOTED_CHAR_PATTERN.matcher(child.getText()).replaceAll("$1");
              }
            })
        .collect(Collectors.joining(""));
  }

  private static @Nonnull String toString(Double_quoted_stringContext ctx) {
    if (ctx.text == null) {
      return "";
    }
    String quotedText = ctx.text.getText();
    return ESCAPED_DOUBLE_QUOTED_CHAR_PATTERN.matcher(quotedText).replaceAll("$1");
  }

  private static @Nonnull String toString(Single_quoted_stringContext ctx) {
    return ctx.text != null ? ctx.text.getText() : "";
  }

  /**
   * Convert a {@link ParserRuleContext} whose text is guaranteed to represent a valid signed 32-bit
   * decimal integer to an {@link Integer} if it is contained in the provided {@code space}, or else
   * {@link Optional#empty}.
   */
  private @Nonnull Optional<Integer> toIntegerInSpace(
      ParserRuleContext messageCtx, ParserRuleContext ctx, IntegerSpace space, String name) {
    int num = Integer.parseInt(ctx.getText());
    if (!space.contains(num)) {
      warn(messageCtx, String.format("Expected %s in range %s, but got '%d'", name, space, num));
      return Optional.empty();
    }
    return Optional.of(num);
  }

  @Override
  public void visitErrorNode(ErrorNode errorNode) {
    Token token = errorNode.getSymbol();
    int line = token.getLine();
    String lineText = errorNode.getText().replace("\n", "").replace("\r", "").trim();
    _c.setUnrecognized(true);

    if (token instanceof UnrecognizedLineToken) {
      UnrecognizedLineToken unrecToken = (UnrecognizedLineToken) token;
      _w.getParseWarnings()
          .add(
              new ParseWarning(
                  line, lineText, unrecToken.getParserContext(), "This syntax is unrecognized"));
    } else {
      String msg = String.format("Unrecognized Line: %d: %s", line, lineText);
      _w.redFlag(msg + " SUBSEQUENT LINES MAY NOT BE PROCESSED CORRECTLY");
    }
  }

  private Optional<Integer> toInteger(ParserRuleContext ctx, Ip_protocol_numberContext num) {
    return toIntegerInSpace(ctx, num, IP_PROTOCOL_NUMBER_SPACE, "ip protocol-number");
  }

  private Optional<Integer> toInteger(ParserRuleContext ctx, MtuContext mtu) {
    return toIntegerInSpace(ctx, mtu, MTU_SPACE, "mtu");
  }

  private Optional<Integer> toInteger(ParserRuleContext ctx, VrfContext vrf) {
    return toIntegerInSpace(ctx, vrf, VRF_SPACE, "vrf");
  }

  private static int toInteger(Subnet_maskContext ctx) {
    return Ip.parse(ctx.getText()).numSubnetBits();
  }

  private static int toInteger(Uint16Context ctx) {
    return Integer.parseInt(ctx.getText());
  }

  private static int toInteger(Uint8Context ctx) {
    return Integer.parseInt(ctx.getText());
  }

  private static @Nonnull Ip toIp(Ip_addressContext ctx) {
    return Ip.parse(ctx.getText());
  }

  private static @Nonnull Ip toIp(Subnet_maskContext ctx) {
    return Ip.parse(ctx.getText());
  }

  private static @Nonnull Ip6 toIp6(Ipv6_addressContext ctx) {
    return Ip6.parse(ctx.getText());
  }

  private static final Pattern DEVICE_HOSTNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+$");
  private static final Pattern ESCAPED_DOUBLE_QUOTED_CHAR_PATTERN =
      Pattern.compile("\\\\(['\"\\\\])");
  private static final Pattern ESCAPED_UNQUOTED_CHAR_PATTERN = Pattern.compile("\\\\([^\\r\\n])");
  private static final Pattern INTERFACE_NAME_PATTERN = Pattern.compile("^[^\r\n]{1,15}$");
  private static final Pattern INTERFACE_ALIAS_PATTERN = Pattern.compile("^[^\r\n]{0,25}$");
  private static final Pattern SERVICE_NAME_PATTERN = Pattern.compile("^[^\r\n]{1,79}$");
  private static final Pattern WORD_PATTERN = Pattern.compile("^[^ \t\r\n]+$");

  private static final IntegerSpace IP_PROTOCOL_NUMBER_SPACE =
      IntegerSpace.of(Range.closed(0, 254));
  private static final IntegerSpace MTU_SPACE = IntegerSpace.of(Range.closed(68, 65535));
  private static final IntegerSpace VRF_SPACE = IntegerSpace.of(Range.closed(0, 31));

  private Interface _currentInterface;
  private Replacemsg _currentReplacemsg;
  private Service _currentService;
  private final @Nonnull FortiosConfiguration _c;
  private final @Nonnull FortiosCombinedParser _parser;
  private final @Nonnull String _text;
  private final @Nonnull Warnings _w;
}
