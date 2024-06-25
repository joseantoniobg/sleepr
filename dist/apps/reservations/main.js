/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/reservations/src/dto/create-reservation.dto.ts":
/*!*************************************************************!*\
  !*** ./apps/reservations/src/dto/create-reservation.dto.ts ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateReservationDto = void 0;
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const common_1 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
class CreateReservationDto {
}
__decorate([
    (0, class_validator_1.IsDate)(),
    (0, class_transformer_1.Type)(() => Date),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], CreateReservationDto.prototype, "startDate", void 0);
__decorate([
    (0, class_validator_1.IsDate)(),
    (0, class_transformer_1.Type)(() => Date),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], CreateReservationDto.prototype, "endDate", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateReservationDto.prototype, "placeId", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateReservationDto.prototype, "invoiceId", void 0);
__decorate([
    (0, class_transformer_1.Type)((value) => common_1.CreateChargeDto),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.IsNotEmptyObject)(),
    (0, class_validator_1.ValidateNested)(),
    __metadata("design:type", typeof (_c = typeof common_1.CreateChargeDto !== "undefined" && common_1.CreateChargeDto) === "function" ? _c : Object)
], CreateReservationDto.prototype, "charge", void 0);
exports.CreateReservationDto = CreateReservationDto;


/***/ }),

/***/ "./apps/reservations/src/dto/update-reservation.dto.ts":
/*!*************************************************************!*\
  !*** ./apps/reservations/src/dto/update-reservation.dto.ts ***!
  \*************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateReservationDto = void 0;
const mapped_types_1 = __webpack_require__(/*! @nestjs/mapped-types */ "@nestjs/mapped-types");
const create_reservation_dto_1 = __webpack_require__(/*! ./create-reservation.dto */ "./apps/reservations/src/dto/create-reservation.dto.ts");
class UpdateReservationDto extends (0, mapped_types_1.PartialType)(create_reservation_dto_1.CreateReservationDto) {
}
exports.UpdateReservationDto = UpdateReservationDto;


/***/ }),

/***/ "./apps/reservations/src/models/reservation.schema.ts":
/*!************************************************************!*\
  !*** ./apps/reservations/src/models/reservation.schema.ts ***!
  \************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReservationSchema = exports.ReservationDocument = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const common_1 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
let ReservationDocument = class ReservationDocument extends common_1.AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], ReservationDocument.prototype, "timestamp", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], ReservationDocument.prototype, "startDate", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], ReservationDocument.prototype, "endDate", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], ReservationDocument.prototype, "userId", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], ReservationDocument.prototype, "placeId", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], ReservationDocument.prototype, "invoiceId", void 0);
ReservationDocument = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false })
], ReservationDocument);
exports.ReservationDocument = ReservationDocument;
exports.ReservationSchema = mongoose_1.SchemaFactory.createForClass(ReservationDocument);


/***/ }),

/***/ "./apps/reservations/src/reservations.controller.ts":
/*!**********************************************************!*\
  !*** ./apps/reservations/src/reservations.controller.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReservationsController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const reservations_service_1 = __webpack_require__(/*! ./reservations.service */ "./apps/reservations/src/reservations.service.ts");
const create_reservation_dto_1 = __webpack_require__(/*! ./dto/create-reservation.dto */ "./apps/reservations/src/dto/create-reservation.dto.ts");
const update_reservation_dto_1 = __webpack_require__(/*! ./dto/update-reservation.dto */ "./apps/reservations/src/dto/update-reservation.dto.ts");
const common_2 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
let ReservationsController = class ReservationsController {
    constructor(reservationsService) {
        this.reservationsService = reservationsService;
    }
    async create(createReservationDto, currentUser) {
        return this.reservationsService.create(createReservationDto, currentUser);
    }
    async findAll() {
        return this.reservationsService.findAll();
    }
    async findOne(id) {
        return this.reservationsService.findOne(id);
    }
    async update(id, updateReservationDto) {
        return this.reservationsService.update(id, updateReservationDto);
    }
    async remove(id) {
        return this.reservationsService.remove(id);
    }
};
__decorate([
    (0, common_1.UseGuards)(common_2.JwtAuthGuard),
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_2.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_reservation_dto_1.CreateReservationDto !== "undefined" && create_reservation_dto_1.CreateReservationDto) === "function" ? _b : Object, typeof (_c = typeof common_2.UserDto !== "undefined" && common_2.UserDto) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], ReservationsController.prototype, "create", null);
__decorate([
    (0, common_1.UseGuards)(common_2.JwtAuthGuard),
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], ReservationsController.prototype, "findAll", null);
__decorate([
    (0, common_1.UseGuards)(common_2.JwtAuthGuard),
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], ReservationsController.prototype, "findOne", null);
__decorate([
    (0, common_1.UseGuards)(common_2.JwtAuthGuard),
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_d = typeof update_reservation_dto_1.UpdateReservationDto !== "undefined" && update_reservation_dto_1.UpdateReservationDto) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], ReservationsController.prototype, "update", null);
__decorate([
    (0, common_1.UseGuards)(common_2.JwtAuthGuard),
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], ReservationsController.prototype, "remove", null);
ReservationsController = __decorate([
    (0, common_1.Controller)('reservations'),
    __metadata("design:paramtypes", [typeof (_a = typeof reservations_service_1.ReservationsService !== "undefined" && reservations_service_1.ReservationsService) === "function" ? _a : Object])
], ReservationsController);
exports.ReservationsController = ReservationsController;


/***/ }),

/***/ "./apps/reservations/src/reservations.module.ts":
/*!******************************************************!*\
  !*** ./apps/reservations/src/reservations.module.ts ***!
  \******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReservationsModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const reservations_service_1 = __webpack_require__(/*! ./reservations.service */ "./apps/reservations/src/reservations.service.ts");
const reservations_controller_1 = __webpack_require__(/*! ./reservations.controller */ "./apps/reservations/src/reservations.controller.ts");
const common_2 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
const reservations_repository_1 = __webpack_require__(/*! ./reservations.repository */ "./apps/reservations/src/reservations.repository.ts");
const reservation_schema_1 = __webpack_require__(/*! ./models/reservation.schema */ "./apps/reservations/src/models/reservation.schema.ts");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const Joi = __webpack_require__(/*! joi */ "joi");
const microservices_1 = __webpack_require__(/*! @nestjs/microservices */ "@nestjs/microservices");
let ReservationsModule = class ReservationsModule {
};
ReservationsModule = __decorate([
    (0, common_1.Module)({
        imports: [config_1.ConfigModule.forRoot({
                isGlobal: true,
                validationSchema: Joi.object({
                    MONGODB_URI: Joi.string().required(),
                    PORT: Joi.number().required(),
                    AUTH_HOST: Joi.string().required(),
                    AUTH_PORT: Joi.number().required(),
                    PAYMENTS_HOST: Joi.string().required(),
                    PAYMENTS_PORT: Joi.number().required(),
                })
            }),
            common_2.DatabaseModule,
            common_2.DatabaseModule.forFeature([{ name: reservation_schema_1.ReservationDocument.name, schema: reservation_schema_1.ReservationSchema }]),
            common_2.LoggerModule,
            microservices_1.ClientsModule.registerAsync([
                {
                    name: common_2.AUTH_SERVICE,
                    useFactory: (configService) => ({
                        name: common_2.AUTH_SERVICE,
                        transport: microservices_1.Transport.TCP,
                        options: {
                            host: configService.get('AUTH_HOST'),
                            port: configService.get('AUTH_PORT')
                        }
                    }),
                    inject: [config_1.ConfigService]
                },
                {
                    name: common_2.PAYMENTS_SERVICE,
                    useFactory: (configService) => ({
                        name: common_2.PAYMENTS_SERVICE,
                        transport: microservices_1.Transport.TCP,
                        options: {
                            host: configService.get('PAYMENTS_HOST'),
                            port: configService.get('PAYMENTS_PORT')
                        }
                    }),
                    inject: [config_1.ConfigService]
                }
            ])
        ],
        controllers: [reservations_controller_1.ReservationsController],
        providers: [reservations_service_1.ReservationsService, reservations_repository_1.ReservationsRepository]
    })
], ReservationsModule);
exports.ReservationsModule = ReservationsModule;


/***/ }),

/***/ "./apps/reservations/src/reservations.repository.ts":
/*!**********************************************************!*\
  !*** ./apps/reservations/src/reservations.repository.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var ReservationsRepository_1;
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReservationsRepository = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const common_2 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
const reservation_schema_1 = __webpack_require__(/*! ./models/reservation.schema */ "./apps/reservations/src/models/reservation.schema.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
let ReservationsRepository = ReservationsRepository_1 = class ReservationsRepository extends common_2.AbstractRepository {
    constructor(reservationModel) {
        super(reservationModel);
        this.logger = new common_1.Logger(ReservationsRepository_1.name);
    }
};
ReservationsRepository = ReservationsRepository_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(reservation_schema_1.ReservationDocument.name)),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object])
], ReservationsRepository);
exports.ReservationsRepository = ReservationsRepository;


/***/ }),

/***/ "./apps/reservations/src/reservations.service.ts":
/*!*******************************************************!*\
  !*** ./apps/reservations/src/reservations.service.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ReservationsService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const reservations_repository_1 = __webpack_require__(/*! ./reservations.repository */ "./apps/reservations/src/reservations.repository.ts");
const common_2 = __webpack_require__(/*! @app/common */ "./libs/common/src/index.ts");
const microservices_1 = __webpack_require__(/*! @nestjs/microservices */ "@nestjs/microservices");
const rxjs_1 = __webpack_require__(/*! rxjs */ "rxjs");
let ReservationsService = class ReservationsService {
    constructor(reservationsRepository, paymentsService) {
        this.reservationsRepository = reservationsRepository;
        this.paymentsService = paymentsService;
    }
    async create(createReservationDto, { email, _id: userId }) {
        return this.paymentsService
            .send('create_charge', Object.assign(Object.assign({}, createReservationDto.charge), { email }))
            .pipe((0, rxjs_1.map)(async (response) => {
            return await this.reservationsRepository.create(Object.assign(Object.assign({}, createReservationDto), { invoiceId: response.id, timestamp: new Date(), userId }));
        }));
    }
    async findAll() {
        return this.reservationsRepository.find({});
    }
    async findOne(id) {
        return this.reservationsRepository.findOne({ _id: id });
    }
    async update(id, updateReservationDto) {
        return this.reservationsRepository.findOneAndUpdate({ _id: id }, { $set: updateReservationDto });
    }
    async remove(id) {
        return this.reservationsRepository.findOneAndDelete({ _id: id });
    }
};
ReservationsService = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(common_2.PAYMENTS_SERVICE)),
    __metadata("design:paramtypes", [typeof (_a = typeof reservations_repository_1.ReservationsRepository !== "undefined" && reservations_repository_1.ReservationsRepository) === "function" ? _a : Object, typeof (_b = typeof microservices_1.ClientProxy !== "undefined" && microservices_1.ClientProxy) === "function" ? _b : Object])
], ReservationsService);
exports.ReservationsService = ReservationsService;


/***/ }),

/***/ "./libs/common/src/auth/index.ts":
/*!***************************************!*\
  !*** ./libs/common/src/auth/index.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./jwt-auth.guard */ "./libs/common/src/auth/jwt-auth.guard.ts"), exports);


/***/ }),

/***/ "./libs/common/src/auth/jwt-auth.guard.ts":
/*!************************************************!*\
  !*** ./libs/common/src/auth/jwt-auth.guard.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtAuthGuard = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const services_1 = __webpack_require__(/*! ../constants/services */ "./libs/common/src/constants/services.ts");
const microservices_1 = __webpack_require__(/*! @nestjs/microservices */ "@nestjs/microservices");
const rxjs_1 = __webpack_require__(/*! rxjs */ "rxjs");
let JwtAuthGuard = class JwtAuthGuard {
    constructor(authClient) {
        this.authClient = authClient;
    }
    canActivate(context) {
        var _a;
        const jwt = (_a = context.switchToHttp().getRequest().cookies) === null || _a === void 0 ? void 0 : _a.Authentication;
        if (!jwt) {
            return false;
        }
        return this.authClient.send('authenticate', {
            Authentication: jwt,
        }).pipe((0, rxjs_1.tap)((resp) => {
            context.switchToHttp().getRequest().user = resp;
        }), (0, rxjs_1.catchError)(() => (0, rxjs_1.of)(false)), (0, rxjs_1.map)(() => true));
    }
};
JwtAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(services_1.AUTH_SERVICE)),
    __metadata("design:paramtypes", [typeof (_a = typeof microservices_1.ClientProxy !== "undefined" && microservices_1.ClientProxy) === "function" ? _a : Object])
], JwtAuthGuard);
exports.JwtAuthGuard = JwtAuthGuard;


/***/ }),

/***/ "./libs/common/src/constants/index.ts":
/*!********************************************!*\
  !*** ./libs/common/src/constants/index.ts ***!
  \********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./services */ "./libs/common/src/constants/services.ts"), exports);


/***/ }),

/***/ "./libs/common/src/constants/services.ts":
/*!***********************************************!*\
  !*** ./libs/common/src/constants/services.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NOTIFICATIONS_SERVICE = exports.PAYMENTS_SERVICE = exports.AUTH_SERVICE = void 0;
exports.AUTH_SERVICE = 'auth';
exports.PAYMENTS_SERVICE = 'payments';
exports.NOTIFICATIONS_SERVICE = 'notifications';


/***/ }),

/***/ "./libs/common/src/database/abstract.repository.ts":
/*!*********************************************************!*\
  !*** ./libs/common/src/database/abstract.repository.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AbstractRepository = void 0;
const mongoose_1 = __webpack_require__(/*! mongoose */ "mongoose");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
class AbstractRepository {
    constructor(model) {
        this.model = model;
    }
    async create(document) {
        const createdDocument = new this.model(Object.assign(Object.assign({}, document), { _id: new mongoose_1.Types.ObjectId() }));
        return (await createdDocument.save()).toJSON();
    }
    async findOne(filterQuery) {
        const document = await this.model.findOne(filterQuery).lean(true);
        if (!document) {
            this.logger.warn('Document not found with filterQuery', filterQuery);
            throw new common_1.NotFoundException('Document not found');
        }
        return document;
    }
    async findOneAndUpdate(filterQuery, updateQuery) {
        const document = await this.model.findOneAndUpdate(filterQuery, updateQuery, { new: true }).lean(true);
        if (!document) {
            this.logger.warn('Document not found with filterQuery', filterQuery);
            throw new common_1.NotFoundException('Document not found');
        }
        return document;
    }
    async find(filterQuery) {
        return this.model.find(filterQuery).lean(true);
    }
    async findOneAndDelete(filterQuery) {
        return await this.model.findOneAndDelete(filterQuery).lean(true);
    }
}
exports.AbstractRepository = AbstractRepository;


/***/ }),

/***/ "./libs/common/src/database/abstract.schema.ts":
/*!*****************************************************!*\
  !*** ./libs/common/src/database/abstract.schema.ts ***!
  \*****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AbstractDocument = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
let AbstractDocument = class AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.SchemaTypes.ObjectId }),
    __metadata("design:type", typeof (_a = typeof mongoose_2.Types !== "undefined" && mongoose_2.Types.ObjectId) === "function" ? _a : Object)
], AbstractDocument.prototype, "_id", void 0);
AbstractDocument = __decorate([
    (0, mongoose_1.Schema)()
], AbstractDocument);
exports.AbstractDocument = AbstractDocument;


/***/ }),

/***/ "./libs/common/src/database/database.module.ts":
/*!*****************************************************!*\
  !*** ./libs/common/src/database/database.module.ts ***!
  \*****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DatabaseModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
let DatabaseModule = class DatabaseModule {
    static forFeature(models) {
        return mongoose_1.MongooseModule.forFeature(models);
    }
};
DatabaseModule = __decorate([
    (0, common_1.Module)({
        imports: [mongoose_1.MongooseModule.forRootAsync({
                useFactory: (configService) => ({
                    uri: configService.get('MONGODB_URI'),
                }),
                inject: [config_1.ConfigService],
            })],
    })
], DatabaseModule);
exports.DatabaseModule = DatabaseModule;


/***/ }),

/***/ "./libs/common/src/database/index.ts":
/*!*******************************************!*\
  !*** ./libs/common/src/database/index.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./database.module */ "./libs/common/src/database/database.module.ts"), exports);
__exportStar(__webpack_require__(/*! ./abstract.repository */ "./libs/common/src/database/abstract.repository.ts"), exports);
__exportStar(__webpack_require__(/*! ./abstract.schema */ "./libs/common/src/database/abstract.schema.ts"), exports);


/***/ }),

/***/ "./libs/common/src/decorators/current-user.decorator.ts":
/*!**************************************************************!*\
  !*** ./libs/common/src/decorators/current-user.decorator.ts ***!
  \**************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CurrentUser = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const getCurrentUserByContext = (context) => {
    return context.switchToHttp().getRequest().user;
};
exports.CurrentUser = (0, common_1.createParamDecorator)((_data, context) => getCurrentUserByContext(context));


/***/ }),

/***/ "./libs/common/src/decorators/index.ts":
/*!*********************************************!*\
  !*** ./libs/common/src/decorators/index.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./current-user.decorator */ "./libs/common/src/decorators/current-user.decorator.ts"), exports);


/***/ }),

/***/ "./libs/common/src/dto/card.dto.ts":
/*!*****************************************!*\
  !*** ./libs/common/src/dto/card.dto.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CardDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CardDto {
}
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CardDto.prototype, "cvc", void 0);
__decorate([
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], CardDto.prototype, "exp_month", void 0);
__decorate([
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], CardDto.prototype, "exp_year", void 0);
exports.CardDto = CardDto;


/***/ }),

/***/ "./libs/common/src/dto/create-charge.dto.ts":
/*!**************************************************!*\
  !*** ./libs/common/src/dto/create-charge.dto.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateChargeDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const card_dto_1 = __webpack_require__(/*! ./card.dto */ "./libs/common/src/dto/card.dto.ts");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
class CreateChargeDto {
}
__decorate([
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.IsNotEmptyObject)(),
    (0, class_validator_1.ValidateNested)(),
    (0, class_transformer_1.Type)((value) => card_dto_1.CardDto),
    __metadata("design:type", typeof (_a = typeof card_dto_1.CardDto !== "undefined" && card_dto_1.CardDto) === "function" ? _a : Object)
], CreateChargeDto.prototype, "card", void 0);
__decorate([
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], CreateChargeDto.prototype, "amount", void 0);
exports.CreateChargeDto = CreateChargeDto;


/***/ }),

/***/ "./libs/common/src/dto/index.ts":
/*!**************************************!*\
  !*** ./libs/common/src/dto/index.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./user.dto */ "./libs/common/src/dto/user.dto.ts"), exports);
__exportStar(__webpack_require__(/*! ./create-charge.dto */ "./libs/common/src/dto/create-charge.dto.ts"), exports);


/***/ }),

/***/ "./libs/common/src/dto/user.dto.ts":
/*!*****************************************!*\
  !*** ./libs/common/src/dto/user.dto.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./libs/common/src/index.ts":
/*!**********************************!*\
  !*** ./libs/common/src/index.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./database */ "./libs/common/src/database/index.ts"), exports);
__exportStar(__webpack_require__(/*! ./logger */ "./libs/common/src/logger/index.ts"), exports);
__exportStar(__webpack_require__(/*! ./auth */ "./libs/common/src/auth/index.ts"), exports);
__exportStar(__webpack_require__(/*! ./constants */ "./libs/common/src/constants/index.ts"), exports);
__exportStar(__webpack_require__(/*! ./decorators */ "./libs/common/src/decorators/index.ts"), exports);
__exportStar(__webpack_require__(/*! ./dto */ "./libs/common/src/dto/index.ts"), exports);


/***/ }),

/***/ "./libs/common/src/logger/index.ts":
/*!*****************************************!*\
  !*** ./libs/common/src/logger/index.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./logger.module */ "./libs/common/src/logger/logger.module.ts"), exports);


/***/ }),

/***/ "./libs/common/src/logger/logger.module.ts":
/*!*************************************************!*\
  !*** ./libs/common/src/logger/logger.module.ts ***!
  \*************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoggerModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const nestjs_pino_1 = __webpack_require__(/*! nestjs-pino */ "nestjs-pino");
let LoggerModule = class LoggerModule {
};
LoggerModule = __decorate([
    (0, common_1.Module)({
        imports: [
            nestjs_pino_1.LoggerModule.forRoot({
                pinoHttp: {
                    transport: {
                        target: 'pino-pretty',
                        options: {
                            singleLine: true,
                        }
                    }
                },
            }),
        ],
    })
], LoggerModule);
exports.LoggerModule = LoggerModule;


/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/mapped-types":
/*!***************************************!*\
  !*** external "@nestjs/mapped-types" ***!
  \***************************************/
/***/ ((module) => {

module.exports = require("@nestjs/mapped-types");

/***/ }),

/***/ "@nestjs/microservices":
/*!****************************************!*\
  !*** external "@nestjs/microservices" ***!
  \****************************************/
/***/ ((module) => {

module.exports = require("@nestjs/microservices");

/***/ }),

/***/ "@nestjs/mongoose":
/*!***********************************!*\
  !*** external "@nestjs/mongoose" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/mongoose");

/***/ }),

/***/ "class-transformer":
/*!************************************!*\
  !*** external "class-transformer" ***!
  \************************************/
/***/ ((module) => {

module.exports = require("class-transformer");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "cookie-parser":
/*!********************************!*\
  !*** external "cookie-parser" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("cookie-parser");

/***/ }),

/***/ "joi":
/*!**********************!*\
  !*** external "joi" ***!
  \**********************/
/***/ ((module) => {

module.exports = require("joi");

/***/ }),

/***/ "mongoose":
/*!***************************!*\
  !*** external "mongoose" ***!
  \***************************/
/***/ ((module) => {

module.exports = require("mongoose");

/***/ }),

/***/ "nestjs-pino":
/*!******************************!*\
  !*** external "nestjs-pino" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("nestjs-pino");

/***/ }),

/***/ "rxjs":
/*!***********************!*\
  !*** external "rxjs" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("rxjs");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!***************************************!*\
  !*** ./apps/reservations/src/main.ts ***!
  \***************************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const reservations_module_1 = __webpack_require__(/*! ./reservations.module */ "./apps/reservations/src/reservations.module.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const nestjs_pino_1 = __webpack_require__(/*! nestjs-pino */ "nestjs-pino");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const cookieParser = __webpack_require__(/*! cookie-parser */ "cookie-parser");
async function bootstrap() {
    const app = await core_1.NestFactory.create(reservations_module_1.ReservationsModule);
    app.useGlobalPipes(new common_1.ValidationPipe({ whitelist: true, transform: true }));
    app.useLogger(app.get(nestjs_pino_1.Logger));
    app.use(cookieParser());
    const configService = app.get(config_1.ConfigService);
    await app.listen(configService.get('PORT'));
}
bootstrap();

})();

/******/ })()
;