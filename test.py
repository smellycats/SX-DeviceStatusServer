import arrow

def create_table():
    t = arrow.get('2015-09-01')
    for i in range(300):
        d1 = t.format('YYYYMMDD')
        d2 = t.format('YYYY-MM-DD')
        t = t.replace(days=3)
        d3 = t.format('YYYY-MM-DD')
        s = "CREATE TABLE traffic_vehicle_pass_{0} (CHECK (pass_time >= DATE '{1}' AND pass_time < DATE '{2}')) INHERITS (traffic_vehicle_pass);".format(d1, d2, d3)
        print s


def create_index():
    t = arrow.get('2015-09-01')
    for i in range(300):
        d1 = t.format('YYYYMMDD')
        #d2 = t.format('YYYY-MM-DD')
        t = t.replace(days=3)
        #d3 = t.format('YYYY-MM-DD')
        print "CREATE INDEX idx_vehiclepass_{0}_com2 ON traffic_vehicle_pass_{0} (pass_time, crossing_id);".format(d1)
        print "CREATE INDEX idx_vehiclepass_{0}_com3 ON traffic_vehicle_pass_{0} (plate_no, pass_time, crossing_id);".format(d1)


def create_trigger():
    print "CREATE OR REPLACE FUNCTION traffic_vehicle_pass_insert_trigger()"
    print "RETURNS TRIGGER AS $$"
    print "BEGIN"
    
    print "    IF ( NEW.pass_time >= DATE '2015-09-01') AND"
    print "         NEW.pass_time < DATE '2015-09-04' ) THEN"
    print "        INSERT INTO traffic_vehicle_pass_20150901 VALUES (NEW.*)"
    print ""
    t = arrow.get('2015-09-04')
    for i in range(299):
        d1 = t.format('YYYYMMDD')
        d2 = t.format('YYYY-MM-DD')
        t = t.replace(days=3)
        d3 = t.format('YYYY-MM-DD')
        print "    ELSIF ( NEW.pass_time >= DATE '{0}') AND".format(d2)
        print "         NEW.pass_time < DATE '{0}' ) THEN".format(d3)
        print "        INSERT INTO traffic_vehicle_pass_{0} VALUES (NEW.*)".format(d1)
        print ""
    print "    ELSE"
    print "        RAISE EXCEPTION 'Date out of range. Fix the traffic_vehicle_pass_insert_trigger() function!';"
    print "    END IF;"
    print "    RETURN NULL;"
    print "END"
    print "&&"
    print "LANGUAGE plpgsql;"

def create_rule():
    t = arrow.get('2015-09-04')
    for i in range(299):
        d1 = t.format('YYYYMMDD')
        d2 = t.format('YYYY-MM-DD')
        t = t.replace(days=3)
        d3 = t.format('YYYY-MM-DD')
        s = """
CREATE RULE insert_tab1_traffic_vehicle_pass_{0} AS 
ON INSERT TO traffic_vehicle_pass WHERE (pass_time >= DATE '{1}' AND pass_time < DATE '{2}')
DO INSTEAD
  INSERT INTO traffic_vehicle_pass_{3} VALUES (NEW.*);
            """.format(d1, d2, d3, d1)
        print s

if __name__ == "__main__":
    #create_table()
    #create_index()
    #create_trigger()
    create_rule()
