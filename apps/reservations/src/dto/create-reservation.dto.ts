import { Type } from "class-transformer";
import { IsDate, IsDefined, IsNotEmpty, IsNotEmptyObject, IsNumber, IsString, ValidateNested } from "class-validator";
import { CreateChargeDto } from "@app/common";

export class CreateReservationDto {
  @IsDate()
  @Type(() => Date)
  startDate: Date;

  @IsDate()
  @Type(() => Date)
  endDate: Date;

  @IsString()
  @IsNotEmpty()
  placeId: string;

  @IsString()
  @IsNotEmpty()
  invoiceId: string;

  @Type((value) => CreateChargeDto)
  @IsDefined()
  @IsNotEmptyObject()
  @ValidateNested()
  charge: CreateChargeDto;
}
