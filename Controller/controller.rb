require 'socket'
require 'rubygems'
#require 'mongo'
#require 'bson'

#Mongo::Logger.logger.level = Logger::FATAL
#Mongo::Logger.logger       = Logger.new('mongo.log')
#Mongo::Logger.logger.level = Logger::INFO

def flag_to_option(flag)
  option = ""
  flag.each{|f|
    option += " "
    opt = f.split(":")[0]
    value = f.split(":")[1]
    case opt
    #スレッド
    when '-T' then
      option += "T #{value}"
    #パケット数
    when '-N' then
      option += "N #{value}"
    #y秒後開始
    when '-y' then
      option += "y #{value}"
    #pcap形式で保存*テスト必要かも
    when '-X' then
      option += "X"
    #pcapng形式で保存*テスト必要かも
    when '-G' then
      option += "G"
    ##### IP HEADER OPTION 
    # 送信元ipを入力したipに偽装する
    when '-s' then
      option += "s #{value}"
    # 送信元ipをランダムに偽装する
    when '-r' then
      option += "r"
    # 送信先ipを入力したipに偽装する
    when '-j' then
      option += "j #{value}"
    # 送信先ipをランダムに偽装する
    when '-J' then
      option += "J"
    # ttlを指定する
    when '-t' then
      option += "t #{value}"
    # flag offsetを指定する
    when '-f' then
      option += "f #{value}"
    # type off serviceを指定する
    when '-o' then
      option += "o #{value}"
    # type off serviceを指定する
    when '-o' then
      option += "o #{value}"
    ##### TCP HEADER OPTION 
    # Window sizeを指定する
    when '-W' then
      option += "W #{value}"
    # Acknowledgment numberを指定する
    when '-L' then
      option += "L #{value}"
    # Sequence numberを指定する
    when '-M' then
      option += "M #{value}"
    # 間違ったチェックサムを指定する
    when '-B' then
      option += "B #{value}"
    # doffを指定する
    when '-O' then
      option += "O #{value}"
    # destination portを指定する
    when '-D' then
      option += "D #{value}"
    # sender portを指定する
    when '-Z' then
      option += "Z #{value}"
    # ACK FLAGを立てる
    when '-A' then
      option += "A"
    # FIN FLAGを立てる
    when '-F' then
      option += "F"
    # PSH FLAGを立てる
    when '-P' then
      option += "P"
    # RST FLAGを立てる
    when '-R' then
      option += "R"
    # URG FLAGを立てる
    when '-U' then
      option += "U"
    # SYN FLAGを立てる
    when '-S' then
      option += "S"
    # ペイロードを載せる 
    when '-d' then
      option += "d #{value}"
    ##### UDP HEADER OPTION 
    # destination portを指定する
    when '-z' then
      option += "z #{value}"
    # sender portを指定する
    when '-d' then
      option += "d #{value}"
    ##### ICMP HEADER OPTION 
    # ICMP TYPEを指定する
    when '-Y' then
      option += "Y #{value}"
    # ICMP codeを指定する
    when '-C' then
      option += "C #{value}"
    # echo/replyの時のICMP idを指定する
    when '-I' then
      option += "I #{value}"
    # echo/replyの時のシーケンスナンバーを指定する
    when '-S' then
      option += "S #{value}"
    end
  }
  return option
end

def print_mode
  puts "mode list"
  puts "===================================="
  puts "1. print connection table"
  puts "2. clear connection table"
  puts "3. generate connection table"
  puts "4. delete connection"
  puts "5. packet manipulate setting"
  puts "6. using scenario manipulate setting"
  puts "7. output pcap log"
  puts "8. output pcapng log"
  puts "9. exit"
  puts "===================================="
  puts 
  puts "input mode id:"
end

def print_all_scenario()
  puts "======================"
  $c.find.each{|row|
    puts "#{row['id'].to_s.rjust(2)} #{row['name']}"
  }
  puts "======================"
  puts 
end

def set_loss(con_id, loss_per, time)
  $sock.print("setloss #{con_id} #{loss_per} #{time}")
  sleep(0.1)
end

def setDelay(con_id, delay, per, difftime)
  $sock.print("setdelay #{con_id} #{delay} #{per} #{difftime}")
  sleep(0.1)
end

def setModify(con_id, before, after, per, difftime)
  $sock.print("setmodify #{con_id} #{before} #{after} #{per} #{difftime}")
  sleep(0.1)
end

def setInsert(con_id, protocol_type, flag)
  if(protocol_type == 'tcp')
    option = flag_to_option(flag)
    puts option
    $sock.print("insert #{con_id} #{protocol_type} #{option}")
  elsif(protocol_type == 'udp')
    option = flag_to_option(flag)
    $sock.print("insert #{con_id} #{protocol_type} #{option}")
  elsif(protocol_type == 'icmp')
    option = flag_to_option(flag)
    $sock.print("insert #{con_id} #{protocol_type} #{option}")
  end
  sleep(0.1)
end

def execScenario(row)
  print "input connection id: "
  cnxid = gets
  set_loss(cnxid, row["loss"], 0) if row["loss"]   != nil
  setDelay(cnxid, row["delay"], 100, 0) if row["delay"]  != nil
  setModify(cnxid, row["before"], row["after"], 100, 0) if row["before"] != nil
#  setInsert()                          if row["insert"] != nil
end

$sock = TCPSocket.open("127.0.0.1", 55555)
#$db = Mongo::Client.new([ '127.0.0.1:27017' ], :database => 'scenario')
#$c = $db[:scenario]
#
loop{
  print_mode
  print "input command num: "
  cmd = gets.to_i
  if cmd == 1
    $sock.print("print")
    puts $sock.recv(10000);
  elsif cmd == 2
    $sock.print("clear")
  elsif cmd == 3
    puts "input Connection table id"
    puts "[source ip] [dest ip] [TCP] [sport] [dport]"
    puts "example:"
    puts "192.168.11.70 192.168.11.80/24 TCP 11111 22222"
    sip, dip, protocol, sport, dport = gets.split(" ")
    puts "generate #{sip} #{dip} #{protocol} #{sport} #{dport}"
    $sock.print("generate #{sip} #{dip} #{protocol} #{sport} #{dport}")
  elsif cmd == 4
    print "input delete id: "
    id = gets.to_i
    if(id <= 0)
      puts("[ERROR] invalid id")
    end
    $sock.print("delete #{id}")
  elsif(cmd == 5)
    puts "manipulate list"
    puts "1. loss"
    puts "2. delay"
    puts "3. modify"
    puts "4. insert"
    puts
    print "input number: "
    manipulate_id = gets.to_i
    if(manipulate_id <= 0 && 5 <= manipulate_id)
      puts "[ERROR] Invalid manipulateid"
      next
    elsif(manipulate_id == 1)
    # loss setting
      puts "input operation"
      puts "[connection id] [loss_per] [time]"
      puts "example:"
      puts "1 100 100"
      con_id, loss_per, time = gets.split(" ")
      set_loss(con_id, loss_per, time)
    elsif(manipulate_id == 2)
    # delay setting
      puts "input delay param"
      puts "[connection_table_id] [delay_time] [percentage ]"
      puts "example:"
      puts "1 10 100"
      con_id, delay_time, per = gets.split(" ")
      setDelay(con_id, delay_time, per, 0);
    # modify setting
    elsif(manipulate_id == 3)
      puts "input modify param"
      puts "[connection_table_id] [before] [after] [per] [difftime]"
      puts "example:"
      puts "1 https http 100 0"
      con_id, before, after, per, difftime = gets.split(" ")
      setModify(con_id, before, after, per, 0);
    # insert setting
    elsif(manipulate_id == 4)
      puts "input insert param"
      puts "[connection_table_id] [protocol type] [flags]"
      puts "example:"
      puts "1 tcp -s:192.168.57.20 -N:1"
      cmd = gets
      con_id = cmd.split(" ")[0]
      protocol_type = cmd.split(" ")[1]
      flags = cmd.split(" ")[2..-1]
      setInsert(con_id, protocol_type, flags)
    end
  elsif cmd == 6
    print_all_scenario()
    print "input scenario_id: "
    scenario_id = gets.to_i
    $c.find('id' => scenario_id).each{|row|
      execScenario(row)
    }
  elsif cmd == 7
  # pcap   
  elsif cmd == 8
  # pcapng   
  else
    $sock.close
    break
  end 
  puts 
}
