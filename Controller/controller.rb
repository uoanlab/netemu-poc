require 'socket'
require 'rubygems'
require 'mongo'
require 'bson'

Mongo::Logger.logger.level = Logger::FATAL
Mongo::Logger.logger       = Logger.new('mongo.log')
Mongo::Logger.logger.level = Logger::INFO


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

def execScenario(row)
  print "input connection id: "
  cnxid = gets
  set_loss(cnxid, row["loss"], 0) if row["loss"]   != nil
  setDelay(cnxid, row["delay"], 100, 0) if row["delay"]  != nil
  setModify(cnxid, row["before"], row["after"], 100, 0) if row["before"] != nil
#  setInsert()                          if row["insert"] != nil
end

$sock = TCPSocket.open("127.0.0.1", 55555)
$db = Mongo::Client.new([ '127.0.0.1:27017' ], :database => 'scenario')
$c = $db[:scenario]

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
    puts "192.168.11.70 192.168.11.80 TCP 11111 22222"
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
      puts "insert"
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
