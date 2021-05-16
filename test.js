const expect = require('chai').expect;
const Events = require('.');

describe('Events.create(options, private_key)', function () {
  it('should create and sign a valid event', function () {
    this.timeout(15000);

    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      var expected_output = {
        iss: test_public,
        typ: 'example',
        pay: {
          "param": "value"
        },
        lt: '0',
        rt: '00',
        dig: '22043f11b0baa33a9119fca6fe701909f533edd9d25a68fdc14921a9a7a0523f',
        sig: '837B83C1010781C74FF03D5F242320BB51C28A0192D11DE53E6848C5D94C23E0AAA5EE610614232665E40A85994EA18D37A33321FAF04B7EB43CB962EEB3B806',
        pow: '??'
      };

      //Act
      var event = Events.create({
        type: 'example',
        payload: {
          "param": "value"
        },
        left: '0',
        right: '00'
      }, test_private);

      var valid = Events.validate(event);

      event = JSON.parse(event);
      //Assert
      try {
        expect(event.iss).to.equal(expected_output.iss);
        expect(event.typ).to.equal(expected_output.typ);
        expect(event.lt).to.equal(expected_output.lt);
        expect(event.rt).to.equal(expected_output.rt);
        expect(event.dig).to.equal(expected_output.dig);
        expect(event.sig).to.equal(expected_output.sig);
        expect(JSON.stringify(event.pay)).to.equal(JSON.stringify(expected_output.pay));
        expect(valid).to.be.true;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

describe('Events.validate(event)', function () {
  it('should return true for a valid event', function () {
    this.timeout(15000);

    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      //Act
      var event = Events.create({
        type: 'example',
        payload: {
          "param": "value"
        },
        left: '0',
        right: '00'
      }, test_private);

      var valid = Events.validate(event);
      //Assert
      try {
        expect(valid).to.be.true;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });

  it('should return false for an invalid event', function () { //note: should really test each way an event can be invalid...
    this.timeout(15000);


    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      //Act
      var event = JSON.parse(Events.create({
        type: 'example',
        payload: {
          "param": "value"
        },
        left: '0',
        right: '00'
      }, test_private));

      //for now, just tamper with the digest
      event.dig = 'aa81611d709dbf43554d4017bf4754315dc6859598200000000000000000000';

      var valid = Events.validate(JSON.stringify(event));
      //Assert
      try {
        expect(valid).to.be.false;
        resolve();
      } catch (e) {
        reject(e);
      }
    });

  });

  it('should return false for a bad proof of work', function () {
    this.timeout(15000);

    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      //Act
      var event = JSON.parse(Events.create({
        type: 'example',
        payload: {
          "param": "value"
        },
        left: 'O',
        right: 'O0',
        tail: 'LO'
      }, test_private));

      //for now, just tamper with the pow
      event.pow = 'foobar';
      var valid = Events.validate(JSON.stringify(event));
      //Assert
      try {
        expect(valid).to.be.false;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

describe('Events.simpleSign(message)', function () {
  it('should sign a simple message', function () {
    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      var expected_output = {
        iss: test_public,
        cnt: {
          "hello": "world"
        },
        dig: 'ee437878485608cd41f3f996a983cb42c2deb541632098280484a2ae73280cad',
        sig: '02AB84F8279A31C257696814D4E2FEC4806A1E3BB0A40FD8DC2CDA461D11252384857EC036A64E1AC3B9CDD8C345BD2FFFCB3A0C54273AF60A35F7BE46DD2509',
      };

      //Act
      var message = Events.simpleSign({
        "hello": "world"
      }, test_private);

      var valid = Events.simpleValidate(message);

      message = JSON.parse(message);
      //Assert
      try {
        expect(message.iss).to.equal(expected_output.iss);
        expect(message.dig).to.equal(expected_output.dig);
        expect(message.sig).to.equal(expected_output.sig);
        expect(JSON.stringify(message.cnt)).to.equal(JSON.stringify(expected_output.cnt));
        expect(valid).to.be.true;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});

describe('Events.simplVerify(message)', function () {
  it('should return true for a valid message', function () {
    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      //Act
      var message = Events.simpleSign({
        "hello": "world"
      }, test_private);

      var valid = Events.simpleValidate(message);

      //Assert
      try {
        expect(valid).to.be.true;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
  it('should return fakse for an invalid message', function () {
    return new Promise(function (resolve, reject) {
      //Arrange
      var test_private = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f';
      var test_public = 'd9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c';

      //Act
      var message = JSON.parse(Events.simpleSign({
        "hello": "world"
      }, test_private));

      message.sig = 'bad!';

      var valid = Events.simpleValidate(JSON.stringify(message));

      //Assert
      try {
        expect(valid).to.be.false;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
});